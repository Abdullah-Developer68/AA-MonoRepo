import { useNavigate } from "react-router-dom";
import useAuth from "../../Hooks/UseAuth";
import api from "../../api/api";
import { toast } from "react-toastify";

const Logout = () => {
  const { user, setUser } = useAuth();
  const navigate = useNavigate();

  const handleLogout = async () => {
    try {
      if (user.googleId) {
        // Google OAuth logout - redirects to server, then back to home with ?googleLogout=true
        // App.jsx will detect the parameter and clear localStorage + user state
        api.googleLogout();
      } else {
        // Regular auth logout - wait for server to clear cookies first
        console.log("Initiating logout - keeping token for server request");
        const response = await api.logout();

        if (response.data.success) {
          console.log("Server logout successful, now clearing client storage");
          localStorage.clear(); // Clear AFTER server confirms logout
          setUser(null); // Clear user state for making routes protected again
          navigate("/login");
          toast.success("Logged out successfully");
        } else {
          throw new Error("Server logout failed");
        }
      }
    } catch (error) {
      console.error("Logout failed:", error);
      toast.error("Failed to logout. Please try again.");

      // If logout fails, still clear client-side data as fallback
      localStorage.clear();
      setUser(null);
      navigate("/login");
    }
  };

  return (
    <button
      onClick={handleLogout}
      className="text-black bg-red-500 px-2 py-1 md:px-3 md:py-2 rounded-md cursor-pointer text-sm md:text-base"
    >
      Logout
    </button>
  );
};

export default Logout;
