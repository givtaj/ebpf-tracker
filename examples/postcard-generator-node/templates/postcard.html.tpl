<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>{{title}}</title>
    <style>
      :root {
        --paper: {{paper}};
        --ink: {{ink}};
        --accent: {{accent}};
        --stamp: {{stamp}};
        --shadow: {{shadow}};
      }

      body {
        margin: 0;
        font-family: Georgia, "Times New Roman", serif;
        background:
          radial-gradient(circle at top left, rgba(255,255,255,0.85), transparent 40%),
          linear-gradient(145deg, #f3ece2, #e1d4c0);
        color: var(--ink);
      }

      main {
        max-width: 1100px;
        margin: 0 auto;
        padding: 48px 20px 72px;
      }

      .hero {
        display: grid;
        gap: 24px;
        grid-template-columns: 1.1fr 0.9fr;
        align-items: start;
      }

      .card {
        background: rgba(255, 255, 255, 0.72);
        border: 1px solid rgba(25, 50, 74, 0.12);
        box-shadow: 0 24px 60px rgba(25, 50, 74, 0.14);
        border-radius: 28px;
        overflow: hidden;
      }

      .art {
        padding: 24px;
        background: linear-gradient(180deg, rgba(255,255,255,0.6), rgba(255,255,255,0.2));
      }

      .art img {
        display: block;
        width: 100%;
        height: auto;
        border-radius: 22px;
      }

      .details {
        padding: 28px;
      }

      h1 {
        margin: 0 0 12px;
        font-size: clamp(2rem, 4vw, 3.6rem);
        line-height: 0.95;
      }

      .lede {
        margin: 0 0 20px;
        font-size: 1.05rem;
        max-width: 34rem;
      }

      .meta {
        display: grid;
        gap: 12px;
        margin: 24px 0;
      }

      .meta div {
        padding: 14px 16px;
        border-radius: 16px;
        background: rgba(248, 242, 231, 0.95);
        border-left: 4px solid var(--accent);
      }

      pre {
        margin: 0;
        padding: 18px;
        border-radius: 18px;
        background: #101b29;
        color: #f4ede0;
        overflow: auto;
        font-size: 0.9rem;
      }

      @media (max-width: 900px) {
        .hero {
          grid-template-columns: 1fr;
        }
      }
    </style>
  </head>
  <body>
    <main>
      <section class="hero">
        <div class="card art">
          <img src="postcard.svg" alt="Generated postcard artwork">
        </div>
        <div class="card details">
          <h1>{{title}}</h1>
          <p class="lede">{{message}}</p>
          <div class="meta">
            <div><strong>Stamp office:</strong> {{server_reply}}</div>
            <div><strong>Generated at:</strong> {{generated_at}}</div>
            <div><strong>Palette:</strong> paper {{paper}}, ink {{ink}}, accent {{accent}}</div>
          </div>
          <pre>{{summary_json}}</pre>
        </div>
      </section>
    </main>
  </body>
</html>
