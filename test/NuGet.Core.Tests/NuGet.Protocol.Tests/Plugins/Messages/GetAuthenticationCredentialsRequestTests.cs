// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.IO;
using Newtonsoft.Json;
using NuGet.Protocol.Plugins;
using NuGet.Protocol.Plugins.Tests;
using Xunit;

namespace NuGet.Protocol.Tests.Plugins.Messages
{
    public class GetAuthenticationCredentialsRequestTests
    {

        [Fact]
        public void Constructor_ThrowsForNullOrEmptyPackageSourceRepository()
        {
            Uri uri = null;
            var exception = Assert.Throws<ArgumentNullException>(
                () => new GetAuthenticationCredentialsRequest(
                    uri: uri,
                    isRetry: false,
                    isNonInteractive: false
                    ));
            Assert.Equal("uri", exception.ParamName);
        }

        [Fact]
        public void Serialization_WorksCorrectly()
        {
            var request = new GetAuthenticationCredentialsRequest(new Uri("https://nuget.org/index.json"), false, true);
            TestSerialization(request);
        }

        public static void TestSerialization<T>(T message) where T : class
        {
            using (var textWriter = new StringWriter())
            {
                using (var jsonWriter = new JsonTextWriter(textWriter))
                {
                    jsonWriter.CloseOutput = false;
                    JsonSerializationUtilities.Serialize(jsonWriter, message);
                    textWriter.WriteLine();
                    textWriter.Flush();
                }

                var deserializedRequest = JsonSerializationUtilities.Deserialize<T>(textWriter.ToString());
                Assert.Equal(message, deserializedRequest);
            }
        }


        [Theory]
        [InlineData("a", null, null, null, null, "{\"PackageSourceRepository\":\"a\"}")]
        [InlineData("a", "b", "c", "d", "e", "{\"PackageSourceRepository\":\"a\",\"Password\":\"e\",\"ProxyPassword\":\"c\",\"ProxyUsername\":\"b\",\"Username\":\"d\"}")]
        public void AJsonSerialization_ReturnsCorrectJson(
    string packageSourceRepository,
    string proxyUsername,
    string proxyPassword,
    string username,
    string password,
    string expectedJson)
        {
            var request = new SetCredentialsRequest(
                packageSourceRepository,
                proxyUsername,
                proxyPassword,
                username,
                password);

            var actualJson = TestUtilities.Serialize(request);

            Assert.Equal(expectedJson, actualJson);
        }

        [Theory]
        [InlineData("{\"PackageSourceRepository\":\"a\"}", "a", null, null, null, null)]
        [InlineData("{\"PackageSourceRepository\":\"a\",\"Password\":\"b\",\"ProxyPassword\":\"c\",\"ProxyUsername\":\"d\",\"Username\":\"e\"}", "a", "d", "c", "e", "b")]
        public void AJsonDeserialization_ReturnsCorrectObject(
            string json,
            string packageSourceRepository,
            string proxyUsername,
            string proxyPassword,
            string username,
            string password)
        {
            var request = JsonSerializationUtilities.Deserialize<SetCredentialsRequest>(json);

            Assert.Equal(packageSourceRepository, request.PackageSourceRepository);
            Assert.Equal(proxyUsername, request.ProxyUsername);
            Assert.Equal(proxyPassword, request.ProxyPassword);
            Assert.Equal(username, request.Username);
            Assert.Equal(password, request.Password);
        }

        [Theory]
        [InlineData("{}")]
        [InlineData("{\"PackageSourceRepository\":null}")]
        [InlineData("{\"PackageSourceRepository\":\"\"}")]
        public void JsonDeserialization_ThrowsForInvalidPackageSourceRepository(string json)
        {
            var exception = Assert.Throws<ArgumentException>(
                () => JsonSerializationUtilities.Deserialize<SetCredentialsRequest>(json));

            Assert.Equal("packageSourceRepository", exception.ParamName);
        }

        // TODO NK - Add these message for every method I need to test.

    }
}
