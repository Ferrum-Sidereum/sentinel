import React from "react";
import { createRoot } from "react-dom/client";
import App from "./App";
import "./style.css";
class ErrorBoundary extends React.Component<React.PropsWithChildren, { failed: boolean }> {
 state = { failed: false };
 static getDerivedStateFromError() { return { failed: true }; }
 render() {
  if (this.state.failed) return <main className="boot"><h1>Sentinel could not render.</h1><p>Close and reopen the window. No error report was uploaded.</p></main>;
  return this.props.children;
 }
}
createRoot(document.getElementById("root")!).render(<ErrorBoundary><App /></ErrorBoundary>);
