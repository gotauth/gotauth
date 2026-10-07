"use client"

import { useCallback, useEffect, useId, useState, type FormEvent } from "react"

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
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
import type { ApiKeyOut, GotAuthError } from "@/lib/gotauth-client"

/** Create, list and delete API keys. A new key is shown once and then dropped. */
export function ApiKeyManager({
  scopes = [],
  organizationId,
}: {
  /** Scopes a new key may get (the server's allowed_scopes). */
  scopes?: string[]
  organizationId?: string
}) {
  const client = useGotAuthClient()
  const id = useId()
  const [keys, setKeys] = useState<ApiKeyOut[] | null>(null)
  const [error, setError] = useState<GotAuthError | null>(null)
  const [open, setOpen] = useState(false)
  // The raw key lives only here, only while the dialog is open.
  const [newKey, setNewKey] = useState<string | null>(null)
  const [copied, setCopied] = useState<"yes" | "failed" | null>(null)
  const [pending, setPending] = useState(false)

  const load = useCallback(async () => {
    const result = await client.apiKeys.listApiKeys(
      organizationId ? { organization_id: organizationId } : {},
    )
    if (result.error) setError(result.error)
    else setKeys(result.data.api_keys)
  }, [client, organizationId])

  useEffect(() => {
    void load()
  }, [load])

  function onOpenChange(next: boolean) {
    setOpen(next)
    if (!next) {
      setNewKey(null)
      setCopied(null)
      setError(null)
    }
  }

  async function create(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const form = new FormData(event.currentTarget)
    setPending(true)
    setError(null)
    const result = await client.apiKeys.createApiKey({
      name: String(form.get("name") ?? ""),
      scopes: form.getAll("scopes").map(String),
      ...(organizationId ? { organization_id: organizationId } : {}),
    })
    setPending(false)
    if (result.error) {
      setError(result.error)
      return
    }
    setNewKey(result.data.key)
    await load()
  }

  async function remove(key: ApiKeyOut) {
    setError(null)
    const result = await client.apiKeys.deleteApiKey(key.id)
    if (result.error) setError(result.error)
    else await load()
  }

  async function copy() {
    if (!newKey) return
    try {
      // navigator.clipboard is missing on plain-http hosts.
      await navigator.clipboard.writeText(newKey)
      setCopied("yes")
    } catch {
      setCopied("failed")
    }
  }

  return (
    <div className="grid gap-4">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold">API keys</h2>
        <Dialog open={open} onOpenChange={onOpenChange}>
          <DialogTrigger asChild>
            <Button>Create key</Button>
          </DialogTrigger>
          <DialogContent>
            {newKey ? (
              <>
                <DialogHeader>
                  <DialogTitle>Copy your new key</DialogTitle>
                  <DialogDescription>
                    This is the only time it's shown. Store it somewhere safe.
                  </DialogDescription>
                </DialogHeader>
                <Alert>
                  <AlertTitle>API key</AlertTitle>
                  <AlertDescription>
                    <code className="break-all" data-testid="new-api-key">
                      {newKey}
                    </code>
                  </AlertDescription>
                </Alert>
                <FormMessage
                  message={
                    copied === "failed"
                      ? "Copying didn't work. Select the key and copy it yourself."
                      : null
                  }
                />
                <DialogFooter>
                  <Button variant="outline" onClick={() => void copy()}>
                    {copied === "yes" ? "Copied" : "Copy key"}
                  </Button>
                  <Button onClick={() => onOpenChange(false)}>Done</Button>
                </DialogFooter>
              </>
            ) : (
              <form className="grid gap-4" onSubmit={(event) => void create(event)}>
                <DialogHeader>
                  <DialogTitle>Create an API key</DialogTitle>
                  <DialogDescription>Give it a name you'll recognize later.</DialogDescription>
                </DialogHeader>
                <div className="grid gap-2">
                  <Label htmlFor={`${id}-name`}>Name</Label>
                  <Input id={`${id}-name`} name="name" required maxLength={100} />
                </div>
                {scopes.length > 0 ? (
                  <fieldset className="grid gap-2">
                    <legend className="text-sm font-medium">Scopes</legend>
                    {scopes.map((scope) => (
                      <div key={scope} className="flex items-center gap-2">
                        <input
                          id={`${id}-scope-${scope}`}
                          type="checkbox"
                          name="scopes"
                          value={scope}
                          className="size-4"
                        />
                        <Label htmlFor={`${id}-scope-${scope}`}>{scope}</Label>
                      </div>
                    ))}
                  </fieldset>
                ) : null}
                <FormMessage error={error} />
                <DialogFooter>
                  <Button type="submit" disabled={pending}>
                    {pending ? "Creating..." : "Create key"}
                  </Button>
                </DialogFooter>
              </form>
            )}
          </DialogContent>
        </Dialog>
      </div>
      {keys && keys.length > 0 ? (
        <Table>
          <TableCaption>Keys that can call the API for you</TableCaption>
          <TableHeader>
            <TableRow>
              <TableHead>Name</TableHead>
              <TableHead>Key</TableHead>
              <TableHead>Scopes</TableHead>
              <TableHead>Last used</TableHead>
              <TableHead>
                <span className="sr-only">Actions</span>
              </TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {keys.map((key) => (
              <TableRow key={key.id}>
                <TableCell>{key.name}</TableCell>
                <TableCell>
                  <code>gak_{key.start}...</code>
                </TableCell>
                <TableCell>{key.scopes.join(", ") || "None"}</TableCell>
                <TableCell>
                  {key.last_used_at ? new Date(key.last_used_at).toLocaleString() : "Never"}
                </TableCell>
                <TableCell className="text-right">
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => void remove(key)}
                    aria-label={`Delete key ${key.name}`}
                  >
                    Delete
                  </Button>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      ) : keys ? (
        <p className="text-muted-foreground text-sm">No API keys yet.</p>
      ) : null}
      {open ? null : <FormMessage error={error} />}
    </div>
  )
}
