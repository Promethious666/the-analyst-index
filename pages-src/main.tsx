import React from "react";
import { createRoot } from "react-dom/client";
import { ToolDirectory } from "../app/tool-directory";
import "../app/globals.css";

const root = document.getElementById("root");

if (!root) {
  throw new Error("Page root is unavailable");
}

createRoot(root).render(
  <React.StrictMode>
    <ToolDirectory />
  </React.StrictMode>,
);
