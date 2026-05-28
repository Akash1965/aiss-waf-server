// Package updater — gRPC CVE delta puller.
// Connects to the central server via /v1/updates HTTP endpoint (JSON).
// The interface matches the future gRPC streaming call so the swap is transparent.
package updater

// GRPCPuller is documented here as an extension point.
// The current CVEPuller in cve_puller.go already implements delta-pull via
// plain HTTP JSON, which is API-compatible with the server's /v1/updates route.
//
// When the server grows a true gRPC streaming endpoint, replace CVEPuller.pull()
// with a grpc.ClientStream call using the AISS proto definition in proto/aiss.proto.
//
// Required proto method:
//   rpc GetCVEUpdates(UpdateRequest) returns (stream CVESignature);
//
// Go client skeleton (activate when grpc server is ready):
//
//   conn, _ := grpc.Dial(serverGRPCAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
//   client  := aissv1pb.NewAISSClient(conn)
//   stream, _ := client.GetCVEUpdates(ctx, &aissv1pb.UpdateRequest{
//       AgentId: agentID,
//       Since:   since,
//       ApiKey:  apiKey,
//   })
//   for {
//       sig, err := stream.Recv()
//       if err == io.EOF { break }
//       reloader.UpsertPattern(int(sig.Id), sig.CveId, sig.Pattern, sig.Severity)
//   }
