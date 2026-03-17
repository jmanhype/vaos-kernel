package grpc

import (
	"context"

	basegrpc "google.golang.org/grpc"
)

// Client provides typed helpers for the kernel services over a shared grpc.ClientConn.
type Client struct {
	conn *basegrpc.ClientConn
}

// NewClient wraps an existing gRPC client connection.
func NewClient(conn *basegrpc.ClientConn) *Client {
	return &Client{conn: conn}
}

func (c *Client) ExecuteSwarmIntent(ctx context.Context, req *Request) (*Response, error) {
	resp := &Response{}
	if err := c.conn.Invoke(ctx, "/vaos.kernel.swarm.v1.SwarmService/ExecuteIntent", req, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

func (c *Client) ExecuteCrucibleTask(ctx context.Context, req *Request) (*Response, error) {
	resp := &Response{}
	if err := c.conn.Invoke(ctx, "/vaos.kernel.crucible.v1.CrucibleService/ExecuteTask", req, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

func (c *Client) DispatchInterface(ctx context.Context, req *Request) (*Response, error) {
	resp := &Response{}
	if err := c.conn.Invoke(ctx, "/vaos.kernel.interface.v1.InterfaceService/Dispatch", req, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

