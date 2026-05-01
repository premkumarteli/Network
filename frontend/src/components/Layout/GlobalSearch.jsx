import { useState } from 'react';
import { useNavigate } from 'react-router-dom';

const GlobalSearch = () => {
  const [query, setQuery] = useState('');
  const navigate = useNavigate();

  const handleSearch = (e) => {
    e.preventDefault();
    if (!query.trim()) return;
    
    // Simple logic: if it looks like an IP, go to user page
    if (/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(query)) {
      navigate(`/user/${encodeURIComponent(query)}`);
    } else {
      // General search could go to a search results page or filter devices
      navigate(`/devices?search=${encodeURIComponent(query)}`);
    }
    setQuery('');
  };

  return (
    <div className="nv-search">
      <form onSubmit={handleSearch} style={{ position: 'relative' }}>
        <i className="ri-search-line icon"></i>
        <input
          type="text"
          placeholder="Search IP, device, application..."
          value={query}
          onChange={(e) => setQuery(e.target.value)}
        />
      </form>
    </div>
  );
};

export default GlobalSearch;
