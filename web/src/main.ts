import "./styles.css";

import { bootstrapDashboard } from "./app/App";

const app = document.querySelector<HTMLElement>("#app");

if (!app) {
  throw new Error("missing #app root");
}

bootstrapDashboard(app);
