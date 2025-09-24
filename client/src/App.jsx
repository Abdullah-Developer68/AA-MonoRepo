import Home from "./pages/Home";
import Shop from "./pages/Shop";
import Signup from "./pages/SignUp";
import Login from "./pages/Login";
import Cart from "./pages/Cart";
import UserHistory from "./pages/UserHistory";
import ProductDes from "./pages/ProductDes";
import ProtectedRoute from "./components/ProtectedRoute";
import Navbar from "./components/Global/Navbar";
import Footer from "./components/Global/Footer";
import Dashboard from "./pages/Dashboard";
import Success from "./pages/Success";
import GoogleAuthSuccess from "./components/GoogleAuthSuccess";
import RecruiterByPass from "./pages/RecruiterByPass";
import { Routes, Route, useLocation, useNavigate } from "react-router-dom";
import { useEffect } from "react";
import { toast } from "react-toastify";
import useAuth from "./Hooks/UseAuth";
import "react-toastify/dist/ReactToastify.css";
import "./App.css";

function App() {
  const location = useLocation();
  const navigate = useNavigate();
  const { setUser } = useAuth();

  // Handle Google logout parameter
  useEffect(() => {
    const urlParams = new URLSearchParams(location.search);
    const googleLogout = urlParams.get("googleLogout");

    if (googleLogout === "true") {
      // Clear localStorage and user state
      localStorage.clear();
      setUser(null);
      toast.success("Successfully logged out from Google");

      // Remove the parameter from URL without triggering a reload
      navigate("/", { replace: true });
    }
  }, [location.search, navigate, setUser]);

  return (
    <>
      <div className="min-h-screen flex flex-col">
        <Navbar />
        <main className="flex-grow">
          <Routes>
            <Route path="/" element={<Home />} />
            <Route path="/login" element={<Login />} />
            <Route path="/signup" element={<Signup />} />
            <Route path="/recruiter" element={<RecruiterByPass />} />
            <Route
              path="/auth/google/success"
              element={<GoogleAuthSuccess />}
            />
            <Route
              path="/cart"
              element={
                <ProtectedRoute>
                  <Cart />
                </ProtectedRoute>
              }
            />
            <Route path="/shop" element={<Shop />} />
            <Route path="/shop/:id" element={<ProductDes />} />
            <Route
              path="/history"
              element={
                <ProtectedRoute>
                  <UserHistory />
                </ProtectedRoute>
              }
            />
            {/* Applying "*" after the link allows routes to work within that component */}
            <Route
              path="/dashboard/*"
              element={
                <ProtectedRoute>
                  <Dashboard />
                </ProtectedRoute>
              }
            />
            <Route path="/success" element={<Success />} />
          </Routes>
        </main>
        <Footer />
      </div>
    </>
  );
}

export default App;
