// Copyright (c) 2015-2021 MinIO, Inc.
//
// This file is part of MinIO Object Storage stack
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package cmd

import (
	"fmt"

	"github.com/fatih/color"
	"github.com/minio/cli"
	json "github.com/minio/colorjson"
	"github.com/minio/mc/pkg/probe"
	"github.com/minio/pkg/console"
)

var adminClusterLinkCmd = cli.Command{
	Name:         "link",
	Usage:        "link with a cluster",
	Action:       mainAdminClusterLink,
	OnUsageError: onUsageError,
	Before:       setGlobalsFromContext,
	Flags:        globalFlags,
	CustomHelpTemplate: `NAME:
  {{.HelpName}} - {{.Usage}}

USAGE:
  {{.HelpName}} TARGET PEER_ALIAS

PEER_ALIAS:
  The mc alias for the cluster to link with.

FLAGS:
  {{range .VisibleFlags}}{{.}}
  {{end}}
EXAMPLES:
  1. Establish a multi-cluster link with minio2
     {{.Prompt}} {{.HelpName}} myminio minio2
`,
}

type clusterMessage struct {
	Status string `json:"status"`
}

func (cm *clusterMessage) String() string {
	return console.Colorize("ClusterMessage", "Cluster link status: "+cm.Status)
}

func (cm *clusterMessage) JSON() string {
	jbytes, err := json.MarshalIndent(cm, "", " ")
	fatalIf(probe.NewError(err), "Unable to marshal into JSON.")

	return string(jbytes)
}

func checkAdminClusterLinkSyntax(ctx *cli.Context) {
	argsNr := len(ctx.Args())
	if argsNr != 1 {
		fatalIf(errInvalidArgument().Trace(ctx.Args().Tail()...),
			"Incorrect number of arguments for cluster link command.")
	}
}

func mainAdminClusterLink(ctx *cli.Context) error {
	checkAdminClusterLinkSyntax(ctx)

	console.SetColor("ClusterMessage", color.New(color.FgGreen))

	args := ctx.Args()
	aliasedURL := args.Get(0)

	client, err := newAdminClient(aliasedURL)
	fatalIf(err, "Unable to initialize admin connection.")

	result, e := client.ClusterLink(globalContext)
	fatalIf(probe.NewError(e).Trace(args...), "Unable to link to cluster")

	fmt.Println(result)

	return nil
}
