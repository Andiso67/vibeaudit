import "./globals.css";

export const metadata = {
  title: "VibeAudit — Dashboard de cliente",
  description: "Semáforo de riesgo y hallazgos de la pre-auditoría VibeAudit",
};

export default function RootLayout({ children }) {
  return (
    <html lang="es">
      <body>{children}</body>
    </html>
  );
}