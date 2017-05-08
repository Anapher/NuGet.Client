﻿// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;

namespace NuGet.Protocol.Plugins
{
    /// <summary>
    /// Plugin constants.
    /// </summary>
    public static class PluginConstants
    {
        /// <summary>
        /// Default idle timeout for plugins.
        /// </summary>
        public static readonly TimeSpan IdleTimeout = TimeSpan.FromMinutes(1);

        /// <summary>
        /// Default command-line arguments for plugins.
        /// </summary>
        public static readonly IEnumerable<string> PluginArguments = new[] { "-Plugin" };

        /// <summary>
        /// The default request timeout set by an initialize request after handshaking.
        /// </summary>
        public static readonly TimeSpan RequestTimeout = TimeSpan.FromSeconds(30);

        /// <summary>
        /// Default shutdown timeout for plugins.
        /// </summary>
        public static readonly TimeSpan ShutdownTimeout = TimeSpan.FromSeconds(3);
    }
}