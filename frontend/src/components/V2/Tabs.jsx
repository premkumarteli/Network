const Tabs = ({ value, onChange, items = [] }) => (
  <div className="nv-tabs" role="tablist">
    {items.map((item) => (
      <button
        key={item.value}
        type="button"
        role="tab"
        aria-selected={value === item.value}
        className={`nv-tab ${value === item.value ? 'is-active' : ''}`.trim()}
        onClick={() => onChange(item.value)}
      >
        {item.icon ? <i className={`${item.icon} mr-2`}></i> : null}
        {item.label}
      </button>
    ))}
  </div>
);

export default Tabs;
