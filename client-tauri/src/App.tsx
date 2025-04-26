import React, { Suspense, lazy } from "react";
import { Route, Switch, Link, Redirect } from "wouter";
const SignPage = lazy(() => import("./pages/SignPage"));
const VerifyPage = lazy(() => import("./pages/VerifyPage"));
import { Toaster } from "react-hot-toast";
import "./App.css";

const App: React.FC = () => (
  <>
    <header className="flex gap-4 p-4 bg-gray-100">
      <Link href="/" className="text-blue-500">
        Sign
      </Link>
      <Link href="/verify" className="text-blue-500">
        Verify
      </Link>
    </header>

    <main className=" mx-auto p-4">
      <Suspense fallback={<div>Loading...</div>}>
        <Switch>
          <Route path="/" component={SignPage} />
          <Route path="/verify" component={VerifyPage} />
          <Route>
            <Redirect to="/" />
          </Route>
        </Switch>
      </Suspense>
      <Toaster position="top-right" />
    </main>
  </>
);

export default App;
