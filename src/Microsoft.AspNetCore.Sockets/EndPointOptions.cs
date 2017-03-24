﻿// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System.Collections.Generic;
using Microsoft.AspNetCore.Authorization;

namespace Microsoft.AspNetCore.Sockets
{
    public class EndPointOptions<TEndPoint> where TEndPoint : EndPoint
    {
        public List<string> Policies { get; set; } = new List<string>();

        public TransportType Transports { get; set; } = TransportType.All;
    }
}