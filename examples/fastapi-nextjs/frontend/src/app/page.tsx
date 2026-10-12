"use client"

import Link from "next/link"
import { useEffect, useState } from "react"

import { Button } from "@/components/ui/button"
import { useSession } from "@/hooks/use-session"

type Project = { id: number; name: string }

function Projects() {
  const [projects, setProjects] = useState<Project[] | null>(null)
  useEffect(() => {
    let live = true
    // The session cookie goes along: same origin.
    fetch("/api/projects")
      .then((response) => (response.ok ? (response.json() as Promise<Project[]>) : []))
      .then((value) => {
        if (live) setProjects(value)
      })
    return () => {
      live = false
    }
  }, [])
  if (!projects) return <p className="text-muted-foreground">Loading projects...</p>
  return (
    <ul className="grid gap-2" data-testid="projects">
      {projects.map((project) => (
        <li key={project.id} className="rounded-md border px-4 py-3">
          {project.name}
        </li>
      ))}
    </ul>
  )
}

export default function Home() {
  const { data, isPending } = useSession()
  if (isPending) return null
  if (!data) {
    return (
      <section className="grid gap-4">
        <h1 className="text-2xl font-semibold">GotAuth example</h1>
        <p className="text-muted-foreground">
          FastAPI and Next.js with email and password, GitHub and API keys.
        </p>
        <div className="flex gap-3">
          <Button asChild>
            <Link href="/sign-in">Sign in</Link>
          </Button>
          <Button asChild variant="outline">
            <Link href="/sign-up">Create an account</Link>
          </Button>
        </div>
      </section>
    )
  }
  return (
    <section className="grid gap-4">
      <h1 className="text-2xl font-semibold">Your projects</h1>
      <p className="text-muted-foreground">Signed in as {data.user.email}</p>
      <Projects />
    </section>
  )
}
