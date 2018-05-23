// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System.Collections.Generic;
using FluentAssertions;
using NuGet.Packaging.Signing;
using Xunit;

namespace NuGet.Packaging.Test
{
    public class SignedPackageVerifierSettingsTests
    {
        [Theory]
        [InlineData(true, VerificationTarget.Author, SignaturePlacement.PrimarySignature, SignatureVerificationBehavior.IfExists)]
        [InlineData(false, VerificationTarget.All, SignaturePlacement.Any, SignatureVerificationBehavior.IfExistsAndIsNecessary)]
        public void ConstructorWithoutLists_InitializesProperties(
            bool boolValue,
            VerificationTarget verificationTarget,
            SignaturePlacement signaturePlacement,
            SignatureVerificationBehavior signatureVerificationBehavior)
        {
            // Arrange & Act
            var settings = new SignedPackageVerifierSettings(
                allowUnsigned: boolValue,
                allowIllegal: boolValue,
                allowUntrusted: boolValue,
                allowIgnoreTimestamp: boolValue,
                allowMultipleTimestamps: boolValue,
                allowNoTimestamp: boolValue,
                allowUnknownRevocation: boolValue,
                verificationTarget: verificationTarget,
                signaturePlacement: signaturePlacement,
                repositoryCountersignatureVerificationBehavior: signatureVerificationBehavior,
                allowNoRepositoryCertificateList: boolValue,
                allowNoClientCertificateList: boolValue);

            // Assert
            settings.AllowUnsigned.Should().Be(boolValue);
            settings.AllowIllegal.Should().Be(boolValue);
            settings.AllowUntrusted.Should().Be(boolValue);
            settings.AllowIgnoreTimestamp.Should().Be(boolValue);
            settings.AllowMultipleTimestamps.Should().Be(boolValue);
            settings.AllowNoTimestamp.Should().Be(boolValue);
            settings.AllowUnknownRevocation.Should().Be(boolValue);
            settings.AllowNoRepositoryCertificateList.Should().Be(boolValue);
            settings.AllowNoClientCertificateList.Should().Be(boolValue);
            settings.RepositoryCountersignatureVerificationBehavior.Should().Be(signatureVerificationBehavior);
        }

        [Theory]
        [InlineData(true, VerificationTarget.Author, SignaturePlacement.PrimarySignature, SignatureVerificationBehavior.IfExists)]
        [InlineData(false, VerificationTarget.All, SignaturePlacement.Any, SignatureVerificationBehavior.IfExistsAndIsNecessary)]
        public void ConstructorWithLists_InitializesProperties(
            bool boolValue,
            VerificationTarget verificationTarget,
            SignaturePlacement signaturePlacement,
            SignatureVerificationBehavior signatureVerificationBehavior)
        {
            // Arrange
            var repoList = new List<CertificateHashAllowListEntry>();
            var clientList = new List<CertificateHashAllowListEntry>();

            // Act
            var settings = new SignedPackageVerifierSettings(
                allowUnsigned: boolValue,
                allowIllegal: boolValue,
                allowUntrusted: boolValue,
                allowIgnoreTimestamp: boolValue,
                allowMultipleTimestamps: boolValue,
                allowNoTimestamp: boolValue,
                allowUnknownRevocation: boolValue,
                allowNoRepositoryCertificateList: boolValue,
                allowNoClientCertificateList: boolValue,
                verificationTarget: verificationTarget,
                signaturePlacement: signaturePlacement,
                repositoryCountersignatureVerificationBehavior: signatureVerificationBehavior,
                repoAllowListEntries: repoList,
                clientAllowListEntries: clientList);

            // Assert
            settings.AllowUnsigned.Should().Be(boolValue);
            settings.AllowIllegal.Should().Be(boolValue);
            settings.AllowUntrusted.Should().Be(boolValue);
            settings.AllowIgnoreTimestamp.Should().Be(boolValue);
            settings.AllowMultipleTimestamps.Should().Be(boolValue);
            settings.AllowNoTimestamp.Should().Be(boolValue);
            settings.AllowUnknownRevocation.Should().Be(boolValue);
            settings.AllowNoRepositoryCertificateList.Should().Be(boolValue);
            settings.AllowNoClientCertificateList.Should().Be(boolValue);
            settings.RepositoryCountersignatureVerificationBehavior.Should().Be(signatureVerificationBehavior);
            settings.RepositoryCertificateList.Should().BeSameAs(repoList);
            settings.ClientCertificateList.Should().BeSameAs(clientList);
        }

        [Fact]
        public void GetDefault_InitializesProperties()
        {
            // Arrange
            var repoList = new List<CertificateHashAllowListEntry>();
            var clientList = new List<CertificateHashAllowListEntry>();
            var defaultValue = true;

            // Act
            var settings = SignedPackageVerifierSettings.GetDefault(repoList, clientList);

            // Assert
            settings.AllowUnsigned.Should().Be(defaultValue);
            settings.AllowIllegal.Should().Be(defaultValue);
            settings.AllowUntrusted.Should().Be(defaultValue);
            settings.AllowIgnoreTimestamp.Should().Be(defaultValue);
            settings.AllowMultipleTimestamps.Should().Be(defaultValue);
            settings.AllowNoTimestamp.Should().Be(defaultValue);
            settings.AllowUnknownRevocation.Should().Be(defaultValue);
            settings.AllowNoRepositoryCertificateList.Should().Be(defaultValue);
            settings.AllowNoClientCertificateList.Should().Be(defaultValue);
            settings.RepositoryCountersignatureVerificationBehavior.Should().Be(SignatureVerificationBehavior.IfExistsAndIsNecessary);
            settings.RepositoryCertificateList.Should().BeSameAs(repoList);
            settings.ClientCertificateList.Should().BeSameAs(clientList);
        }

        [Fact]
        public void GetAcceptModeDefaultPolicy_InitializesProperties()
        {
            // Arrange
            var repoList = new List<CertificateHashAllowListEntry>();
            var clientList = new List<CertificateHashAllowListEntry>();
            var defaultValue = true;

            // Act
            var settings = SignedPackageVerifierSettings.GetAcceptModeDefaultPolicy(repoList, clientList);

            // Assert
            settings.AllowUnsigned.Should().Be(defaultValue);
            settings.AllowIllegal.Should().Be(defaultValue);
            settings.AllowUntrusted.Should().Be(defaultValue);
            settings.AllowIgnoreTimestamp.Should().Be(defaultValue);
            settings.AllowMultipleTimestamps.Should().Be(defaultValue);
            settings.AllowNoTimestamp.Should().Be(defaultValue);
            settings.AllowUnknownRevocation.Should().Be(defaultValue);
            settings.AllowNoRepositoryCertificateList.Should().Be(defaultValue);
            settings.AllowNoClientCertificateList.Should().Be(defaultValue);
            settings.RepositoryCountersignatureVerificationBehavior.Should().Be(SignatureVerificationBehavior.IfExistsAndIsNecessary);
            settings.RepositoryCertificateList.Should().BeSameAs(repoList);
            settings.ClientCertificateList.Should().BeSameAs(clientList);
        }

        [Fact]
        public void GetRequireModeDefaultPolicy_InitializesProperties()
        {
            // Arrange
            var repoList = new List<CertificateHashAllowListEntry>();
            var clientList = new List<CertificateHashAllowListEntry>();

            // Act
            var settings = SignedPackageVerifierSettings.GetRequireModeDefaultPolicy(repoList, clientList);

            // Assert
            settings.AllowUnsigned.Should().Be(false);
            settings.AllowIllegal.Should().Be(false);
            settings.AllowUntrusted.Should().Be(false);
            settings.AllowIgnoreTimestamp.Should().Be(true);
            settings.AllowMultipleTimestamps.Should().Be(true);
            settings.AllowNoTimestamp.Should().Be(true);
            settings.AllowUnknownRevocation.Should().Be(true);
            settings.AllowNoRepositoryCertificateList.Should().Be(false);
            settings.AllowNoClientCertificateList.Should().Be(false);
            settings.RepositoryCountersignatureVerificationBehavior.Should().Be(SignatureVerificationBehavior.IfExistsAndIsNecessary);
            settings.RepositoryCertificateList.Should().BeSameAs(repoList);
            settings.ClientCertificateList.Should().BeSameAs(clientList);
        }

        [Fact]
        public void GetVerifyCommandDefaultPolicy_InitializesProperties()
        {
            // Arrange
            var repoList = new List<CertificateHashAllowListEntry>();
            var clientList = new List<CertificateHashAllowListEntry>();

            // Act
            var settings = SignedPackageVerifierSettings.GetVerifyCommandDefaultPolicy(repoList, clientList);

            // Assert
            settings.AllowUnsigned.Should().Be(false);
            settings.AllowIllegal.Should().Be(false);
            settings.AllowUntrusted.Should().Be(false);
            settings.AllowIgnoreTimestamp.Should().Be(false);
            settings.AllowMultipleTimestamps.Should().Be(true);
            settings.AllowNoTimestamp.Should().Be(true);
            settings.AllowUnknownRevocation.Should().Be(true);
            settings.AllowNoRepositoryCertificateList.Should().Be(true);
            settings.AllowNoClientCertificateList.Should().Be(true);
            settings.RepositoryCountersignatureVerificationBehavior.Should().Be(SignatureVerificationBehavior.IfExists);
            settings.RepositoryCertificateList.Should().BeSameAs(repoList);
            settings.ClientCertificateList.Should().BeSameAs(clientList);
        }
    }
}