import { setupServer } from "msw/node"

export const BASE = "http://localhost/api/auth"
export const server = setupServer()
