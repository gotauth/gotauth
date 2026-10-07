"use client"

import { useCallback, useEffect, useState } from "react"

import { Button } from "@/components/ui/button"
import {
  Table,
  TableBody,
  TableCaption,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import { useGotAuthClient } from "@/components/gotauth/gotauth-provider"
import { FormMessage } from "@/components/gotauth/form-message"
import type { GotAuthError, SessionListOut } from "@/lib/gotauth-client"

function device(userAgent: string | null): string {
  if (!userAgent) return "Unknown device"
  const browser = /Edg\//.test(userAgent)
    ? "Edge"
    : /Firefox\//.test(userAgent)
      ? "Firefox"
      : /Chrome\//.test(userAgent)
        ? "Chrome"
        : /Safari\//.test(userAgent)
          ? "Safari"
          : "Browser"
  const os = /Windows/.test(userAgent)
    ? "Windows"
    : /Android/.test(userAgent)
      ? "Android"
      : /iPhone|iPad/.test(userAgent)
        ? "iOS"
        : /Mac OS X/.test(userAgent)
          ? "macOS"
          : /Linux/.test(userAgent)
            ? "Linux"
            : ""
  return os ? `${browser} on ${os}` : browser
}

/** The user's sessions, with buttons to sign out one or all other devices. */
export function SessionList({ onCurrentRevoked }: { onCurrentRevoked?: () => void }) {
  const client = useGotAuthClient()
  const [list, setList] = useState<SessionListOut | null>(null)
  const [error, setError] = useState<GotAuthError | null>(null)
  const [message, setMessage] = useState<string | null>(null)
  const [busy, setBusy] = useState<string | null>(null)

  const load = useCallback(async () => {
    const result = await client.listSessions()
    if (result.error) setError(result.error)
    else setList(result.data)
  }, [client])

  useEffect(() => {
    void load()
  }, [load])

  async function revoke(sessionId: string) {
    setBusy(sessionId)
    setError(null)
    const result = await client.revokeSession({ session_id: sessionId })
    setBusy(null)
    if (result.error) {
      setError(result.error)
      return
    }
    if (sessionId === list?.current_session_id) {
      onCurrentRevoked?.()
      return
    }
    setMessage("Signed out that device.")
    await load()
  }

  async function revokeOthers() {
    setBusy("others")
    setError(null)
    const result = await client.revokeOtherSessions()
    setBusy(null)
    if (result.error) {
      setError(result.error)
      return
    }
    setMessage("Signed out every other device.")
    await load()
  }

  if (!list) return <FormMessage error={error} message={error ? null : "Loading sessions..."} />
  const others = list.sessions.filter((s) => s.id !== list.current_session_id)
  return (
    <div className="grid gap-4">
      <Table>
        <TableCaption>Devices signed in to your account</TableCaption>
        <TableHeader>
          <TableRow>
            <TableHead>Device</TableHead>
            <TableHead>IP address</TableHead>
            <TableHead>Last active</TableHead>
            <TableHead>
              <span className="sr-only">Actions</span>
            </TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {list.sessions.map((session) => {
            const current = session.id === list.current_session_id
            return (
              <TableRow key={session.id}>
                <TableCell>
                  {device(session.user_agent)}
                  {current ? <span className="text-muted-foreground"> (this device)</span> : null}
                </TableCell>
                <TableCell>{session.ip_address ?? "Unknown"}</TableCell>
                <TableCell>
                  <time dateTime={session.updated_at}>
                    {new Date(session.updated_at).toLocaleString()}
                  </time>
                </TableCell>
                <TableCell className="text-right">
                  <Button
                    variant="outline"
                    size="sm"
                    disabled={busy !== null}
                    onClick={() => void revoke(session.id)}
                    aria-label={current ? "Sign out of this device" : `Sign out ${device(session.user_agent)}`}
                  >
                    Sign out
                  </Button>
                </TableCell>
              </TableRow>
            )
          })}
        </TableBody>
      </Table>
      {others.length > 0 ? (
        <Button variant="outline" disabled={busy !== null} onClick={() => void revokeOthers()}>
          Sign out all other devices
        </Button>
      ) : null}
      <FormMessage error={error} message={message} />
    </div>
  )
}
