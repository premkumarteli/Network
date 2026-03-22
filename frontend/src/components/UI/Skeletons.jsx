const StatGridSkeleton = ({ count = 4 }) => (
  <div className="kpi-grid">
    {Array.from({ length: count }).map((_, index) => (
      <div key={index} className="skeleton-card shimmer">
        <div className="skeleton-line short"></div>
        <div className="skeleton-line large"></div>
        <div className="skeleton-line medium"></div>
      </div>
    ))}
  </div>
);

const TableSkeleton = ({ rows = 6 }) => (
  <div className="table-skeleton">
    {Array.from({ length: rows }).map((_, index) => (
      <div key={index} className="table-skeleton__row shimmer">
        <div className="skeleton-line medium"></div>
        <div className="skeleton-line short"></div>
        <div className="skeleton-line short"></div>
        <div className="skeleton-line medium"></div>
      </div>
    ))}
  </div>
);

const DetailSkeleton = () => (
  <div className="detail-skeleton">
    <div className="detail-skeleton__hero shimmer"></div>
    <div className="kpi-grid">
      <div className="skeleton-card shimmer"></div>
      <div className="skeleton-card shimmer"></div>
      <div className="skeleton-card shimmer"></div>
    </div>
    <div className="table-skeleton">
      {Array.from({ length: 4 }).map((_, index) => (
        <div key={index} className="table-skeleton__row shimmer">
          <div className="skeleton-line medium"></div>
          <div className="skeleton-line short"></div>
          <div className="skeleton-line medium"></div>
        </div>
      ))}
    </div>
  </div>
);

export { DetailSkeleton, StatGridSkeleton, TableSkeleton };
