import { invoke } from "@tauri-apps/api/core";
import "./App.css";

function App() {
  async function greet() {
    // Learn more about Tauri commands at https://tauri.app/develop/calling-rust/
    await invoke("greet", { name: "hjogehoge" });
  }

  return (
    <main className="container">
      <h1>Welcome to Tauri + React</h1>

      <form
        className="row"
        onSubmit={(e) => {
          e.preventDefault();
          greet();
        }}
      >
        <input id="greet-input" placeholder="Enter a name..." />
        <button type="submit">Greet</button>
      </form>
    </main>
  );
}

export default App;
