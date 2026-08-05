import { env } from "./env.js";
import { createApp } from "./app.js";

const app = createApp();

app.listen(env.port, () => {
  console.log(`JoJoX backend in ascolto sulla porta ${env.port}`);
});
