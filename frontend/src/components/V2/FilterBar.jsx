const FilterBar = ({ children, className = '' }) => (
  <div className={`nv-filterbar ${className}`.trim()}>
    {children}
  </div>
);

export default FilterBar;
