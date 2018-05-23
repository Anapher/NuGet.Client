// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using NuGet.Common;

namespace NuGet.Packaging.Signing
{
    public class SignatureTrustAndValidityVerificationProvider : ISignatureVerificationProvider
    {
        private readonly HashAlgorithmName _fingerprintAlgorithm;

        public SignatureTrustAndValidityVerificationProvider()
        {
            _fingerprintAlgorithm = HashAlgorithmName.SHA256;
        }

        public Task<PackageVerificationResult> GetTrustResultAsync(
            ISignedPackageReader package,
            PrimarySignature signature,
            SignedPackageVerifierSettings settings,
            CancellationToken token)
        {
            token.ThrowIfCancellationRequested();

            if (package == null)
            {
                throw new ArgumentNullException(nameof(package));
            }

            if (signature == null)
            {
                throw new ArgumentNullException(nameof(signature));
            }

            if (settings == null)
            {
                throw new ArgumentNullException(nameof(settings));
            }

            var result = Verify(signature, settings);

            return Task.FromResult(result);
        }

#if IS_DESKTOP
        private PackageVerificationResult Verify(
            PrimarySignature signature,
            SignedPackageVerifierSettings settings)
        {
            var issues = new List<SignatureLog>();
            var certificateExtraStore = signature.SignedCms.Certificates;
            var repositoryCountersignatureExists = SignatureUtility.HasRepositoryCountersignature(signature);
            var isRepositoryCountersignatureVerificationRequested = settings.VerificationTarget.HasFlag(VerificationTarget.Repository) &&
                settings.SignaturePlacement.HasFlag(SignaturePlacement.Countersignature);
            var allowDeferralToRepositoryCountersignature = isRepositoryCountersignatureVerificationRequested &&
                repositoryCountersignatureExists;
            var status = SignatureVerificationStatus.Unknown;

            // Only accept untrusted root if the signature has a countersignature that we can validate against
            var verifySettings = new SignatureVerifySettings(
                treatIssuesAsErrors: !settings.AllowIllegal,
                allowUntrustedRoot: allowDeferralToRepositoryCountersignature,
                allowUnknownRevocation: settings.AllowUnknownRevocation,
                logOnSignatureExpired: !allowDeferralToRepositoryCountersignature);

            SignatureVerificationSummary primarySummary = null;

            if (settings.SignaturePlacement.HasFlag(SignaturePlacement.PrimarySignature) &&
                VerificationUtility.IsMatch(signature.Type, settings.VerificationTarget))
            {
                primarySummary = VerifyValidityAndTrust(signature, settings, verifySettings, certificateExtraStore, issues);

                status = primarySummary.Status;
            }

            var shouldVerifyRepositoryCountersignature = false;

            switch (settings.RepositoryCountersignatureVerificationBehavior)
            {
                case SignatureVerificationBehavior.IfExists:
                    shouldVerifyRepositoryCountersignature = isRepositoryCountersignatureVerificationRequested &&
                        repositoryCountersignatureExists;
                    break;

                case SignatureVerificationBehavior.IfExistsAndIsNecessary:
                    shouldVerifyRepositoryCountersignature = isRepositoryCountersignatureVerificationRequested &&
                        repositoryCountersignatureExists &&
                        primarySummary != null &&
                        ShouldFallbackToRepositoryCountersignature(primarySummary);
                    break;

                case SignatureVerificationBehavior.Always:
                    shouldVerifyRepositoryCountersignature = isRepositoryCountersignatureVerificationRequested;
                    break;

                default:
                    throw new NotImplementedException();
            }

            if (shouldVerifyRepositoryCountersignature)
            {
                var countersignature = RepositoryCountersignature.GetRepositoryCountersignature(signature);

                if (countersignature == null)
                {
                    if (settings.RepositoryCountersignatureVerificationBehavior == SignatureVerificationBehavior.Always)
                    {
                        status = SignatureVerificationStatus.Disallowed;
                    }
                }
                else
                {
                    verifySettings = new SignatureVerifySettings(
                        treatIssuesAsErrors: !settings.AllowIllegal,
                        allowUntrustedRoot: settings.AllowUntrusted,
                        allowUnknownRevocation: settings.AllowUnknownRevocation,
                        logOnSignatureExpired: true);

                    var countersignatureSummary = VerifyValidityAndTrust(countersignature, settings, verifySettings, certificateExtraStore, issues);

                    if (primarySummary == null)
                    {
                        status = countersignatureSummary.Status;
                    }
                    else if (primarySummary.Status == SignatureVerificationStatus.Untrusted &&
                        countersignatureSummary.Status == SignatureVerificationStatus.Valid)
                    {
                        status = SignatureVerificationStatus.Valid;
                    }
                    else
                    {
                        status = (SignatureVerificationStatus)Math.Min((int)countersignatureSummary.Status, (int)primarySummary.Status);
                    }

                    if (countersignatureSummary.Timestamp != null &&
                        !Rfc3161TimestampVerificationUtility.ValidateSignerCertificateAgainstTimestamp(signature.SignerInfo.Certificate, countersignatureSummary.Timestamp))
                    {
                        issues.Add(
                            SignatureLog.Issue(
                                !settings.AllowIllegal,
                                NuGetLogCode.NU3011,
                                string.Format(CultureInfo.CurrentCulture, Strings.VerifyError_SignatureNotTimeValid, signature.FriendlyName)));
                        status = SignatureVerificationStatus.Illegal;
                    }
                }
            }

            return new SignedPackageVerificationResult(status, signature, issues);
        }

        private SignatureVerificationSummary GetTimestamp(
            Signature signature,
            SignedPackageVerifierSettings verifierSettings,
            List<SignatureLog> issues,
            out Timestamp timestamp)
        {
            SignatureVerificationStatus status;
            SignatureVerificationStatusFlags statusFlags;

            var succeeded = signature.TryGetValidTimestamp(verifierSettings, _fingerprintAlgorithm, issues, out statusFlags, out timestamp);

            status = VerificationUtility.GetSignatureVerificationStatus(statusFlags);

            if (!succeeded && statusFlags == SignatureVerificationStatusFlags.MultipleTimestamps)
            {
                status = SignatureVerificationStatus.Disallowed;
            }

            return new SignatureVerificationSummary(signature.Type, status, statusFlags);
        }

        private SignatureVerificationSummary VerifyValidityAndTrust(
            Signature signature,
            SignedPackageVerifierSettings verifierSettings,
            SignatureVerifySettings settings,
            X509Certificate2Collection certificateExtraStore,
            List<SignatureLog> issues)
        {
            Timestamp timestamp;
            var timestampStatus = GetTimestamp(signature, verifierSettings, issues, out timestamp);

            if (timestampStatus.Status != SignatureVerificationStatus.Valid && !verifierSettings.AllowIgnoreTimestamp)
            {
                return new SignatureVerificationSummary(
                    signature.Type,
                    SignatureVerificationStatus.Disallowed,
                    SignatureVerificationStatusFlags.NoValidTimestamp);
            }

            var status = signature.Verify(
                timestamp,
                settings,
                _fingerprintAlgorithm,
                certificateExtraStore,
                issues);

            return status;
        }

        private bool ShouldFallbackToRepositoryCountersignature(SignatureVerificationSummary primarySummary)
        {
            return primarySummary.SignatureType == SignatureType.Author &&
                ((primarySummary.Status == SignatureVerificationStatus.Untrusted &&
                primarySummary.Flags == SignatureVerificationStatusFlags.CertificateExpired) ||
                (primarySummary.Status == SignatureVerificationStatus.Valid &&
                primarySummary.Flags.HasFlag(SignatureVerificationStatusFlags.UntrustedRoot)));
        }

#else
        private PackageVerificationResult Verify(
            PrimarySignature signature,
            SignedPackageVerifierSettings settings)
        {
            throw new NotSupportedException();
        }
#endif
    }
}