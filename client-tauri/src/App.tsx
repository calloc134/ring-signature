import { BrowserRouter, Routes, Route, Link } from "react-router-dom";
import SignPage from "./SignPage";
import VerifyPage from "./VerifyPage";
import { Toaster } from "react-hot-toast";
import "./App.css";

function App() {
  return (
    <BrowserRouter>
      <div className="container mx-auto p-4">
        <nav className="flex space-x-4 mb-4">
          <Link to="/sign" className="text-blue-500 hover:underline">
            Sign
          </Link>
          <Link to="/verify" className="text-blue-500 hover:underline">
            Verify
          </Link>
        </nav>
        <Routes>
          <Route path="/sign" element={<SignPage />} />
          <Route path="/verify" element={<VerifyPage />} />
          <Route path="*" element={<SignPage />} />
        </Routes>
      </div>
      <Toaster position="top-right" />
    </BrowserRouter>
  );
}

export default App;
