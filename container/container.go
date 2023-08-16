package container

import (
	"context"

	protoapi "github.com/Encedeus/protobuf/panel"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/strslice"
	docker "github.com/docker/docker/client"
	"github.com/docker/go-connections/nat"
)

type ContainerServer struct {
    protoapi.UnimplementedContainerServer
    Client *docker.Client
}

func (cs ContainerServer) Create(ctx context.Context, params *protoapi.ContainerCreateParams) (*protoapi.ContainerCreateResp, error) {
    var exposedPorts nat.PortSet
    for _, p := range params.GetConfig().GetExposedPorts() {
        exposedPorts[nat.Port(p.GetValue())] = struct{}{}
    }

    dresp, err := cs.Client.ContainerCreate(
        ctx, 
        &container.Config{
            Image: params.GetConfig().GetImage(),
            Tty: params.GetConfig().GetTty(),
            AttachStdin: params.GetConfig().GetAttachStdin(),
            AttachStdout: params.GetConfig().GetAttachStdout(),
            AttachStderr: params.GetConfig().GetAttachStderr(),
            Cmd: strslice.StrSlice(params.GetConfig().GetCmd()),
            WorkingDir: params.GetConfig().GetWorkingDir(),
            Env: params.GetConfig().GetEnv(),
            ExposedPorts: exposedPorts,
        },
        &container.HostConfig{},
        nil,
        nil,
        params.GetName(),
    )
    if err != nil {
        return nil, err
    }

    resp := &protoapi.ContainerCreateResp{
        ID: dresp.ID,
        Warnings: dresp.Warnings,
    }

    return resp, nil
}
