import type { ReactNode } from "react"

import { Header } from "./header"
import { Providers } from "./providers"

import "./globals.css"

export const metadata = { title: "GotAuth example" }

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body className="min-h-screen bg-background text-foreground antialiased">
        <Providers>
          <Header />
          <main className="mx-auto grid max-w-3xl gap-6 p-6">{children}</main>
        </Providers>
      </body>
    </html>
  )
}
