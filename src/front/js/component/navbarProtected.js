import React from "react";
import { Link } from "react-router-dom";

export const NavbarProtected = () => {
  return (
    <nav className="navbar navbar-light bg-light">
      <div className="container">
        <Link to="/">
          <span className="navbar-brand mb-0 h1">React Boilerplate</span>
        </Link>
        <div className="ml-auto">
          <Link to="/profile">
            <button className="btn btn-primary mx-2">Perfil</button>
          </Link>
          <Link to="/logout">
            <button className="btn btn-primary mx-2">Logout</button>
          </Link>
        </div>
      </div>
    </nav>
  );
};
