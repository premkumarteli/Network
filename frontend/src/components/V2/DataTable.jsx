const DataTable = ({
  columns = [],
  rows = [],
  rowKey = 'id',
  onRowClick,
  emptyTitle = 'No data',
  emptyDescription = 'There is nothing to show in this view yet.',
  className = '',
}) => {
  const resolveRowKey = (row, index) => {
    if (typeof rowKey === 'function') {
      return rowKey(row, index);
    }
    return row?.[rowKey] ?? index;
  };

  const handleRowKeyDown = (event, row) => {
    if (!onRowClick) {
      return;
    }
    if (event.key === 'Enter' || event.key === ' ') {
      event.preventDefault();
      onRowClick(row);
    }
  };

  return (
    <div className={`nv-table-shell ${className}`.trim()}>
      <div className="nv-table-wrap">
        <table className="nv-table">
          <thead>
            <tr>
              {columns.map((column) => (
                <th key={column.key || column.label} className={column.headerClassName || ''}>
                  {column.label}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.length === 0 ? (
              <tr>
                <td colSpan={columns.length}>
                  <div className="nv-empty" style={{ background: 'transparent', boxShadow: 'none', border: '0', padding: '2rem' }}>
                    <div className="nv-empty__icon">
                      <i className="ri-inbox-archive-line"></i>
                    </div>
                    <div className="nv-stack" style={{ gap: '0.5rem' }}>
                      <h3 className="nv-empty__title">{emptyTitle}</h3>
                      <p className="nv-empty__description">{emptyDescription}</p>
                    </div>
                  </div>
                </td>
              </tr>
            ) : (
              rows.map((row, index) => (
                <tr
                  key={resolveRowKey(row, index)}
                  className={onRowClick ? 'is-clickable' : ''}
                  onClick={onRowClick ? () => onRowClick(row) : undefined}
                  onKeyDown={(event) => handleRowKeyDown(event, row)}
                  tabIndex={onRowClick ? 0 : undefined}
                >
                  {columns.map((column) => (
                    <td key={column.key || column.label} className={column.className || ''}>
                      {column.render ? column.render(row, index) : row?.[column.key]}
                    </td>
                  ))}
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default DataTable;
