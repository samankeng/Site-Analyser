import React from 'react';

const NotFound = () => {
  return (
    <div className="container mt-5 text-center">
      <h1 className="display-4">404 - Page Not Found</h1>
      <p className="lead">The page you are looking for does not exist.</p>
      <div className="mt-4">
        <a href="/" className="btn btn-primary">
          Return to Home
        </a>
      </div>
    </div>
  );
};

export default NotFound;