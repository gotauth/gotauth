"use client"

import { useMemo } from "react"
import { encode } from "uqr"

/** A QR code drawn in the page as SVG. The text (an otpauth:// URI with the TOTP
 * secret) never leaves the browser. */
export function QrCode({ value, label, size = 192 }: { value: string; label: string; size?: number }) {
  const { cells, width } = useMemo(() => {
    const qr = encode(value, { ecc: "M", border: 2 })
    const dark: string[] = []
    qr.data.forEach((row, y) =>
      row.forEach((on, x) => {
        if (on) dark.push(`M${x} ${y}h1v1h-1z`)
      }),
    )
    return { cells: dark.join(""), width: qr.size }
  }, [value])
  return (
    <svg
      role="img"
      aria-label={label}
      viewBox={`0 0 ${width} ${width}`}
      width={size}
      height={size}
      shapeRendering="crispEdges"
      className="rounded-md bg-white"
    >
      <rect width={width} height={width} fill="#fff" />
      <path d={cells} fill="#000" />
    </svg>
  )
}
