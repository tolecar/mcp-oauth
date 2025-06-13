# MCP OAuth2 Server Plugin

This WordPress plugin provides a minimal OAuth2 server optimized for Model Context Protocol (MCP) usage.

## Features

- Authorization Code and Refresh Token grants
- Stores client and token data using WordPress custom post types
- Exposes REST API endpoints under `/wp-json/mcp/v1`:
  - `GET /authorize`
  - `POST /token`

This plugin implements the OAuth2 *Authorization Code* flow and issues
refresh tokens so clients can obtain new access tokens without user
interaction.  Tokens are returned as JSON and are compatible with the
authentication scheme described in the Model Context Protocol.

Refer to the [Model Context Protocol specification](https://modelcontextprotocol.io/specification/2025-03-26/basic/authorization) for full details on how requests should be authenticated.
