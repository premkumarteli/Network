const InsightList = ({ items = [] }) => (
  <div className="nv-insight-list">
    {items.map((item, index) => {
      const content = (
        <>
          {item.icon ? (
            <span className="nv-insight-item__icon">
              <i className={item.icon}></i>
            </span>
          ) : null}
          <div className="nv-insight-item__body">
            <strong>{item.title}</strong>
            {item.description ? <p>{item.description}</p> : null}
          </div>
          {item.meta ? <div className="nv-insight-item__meta">{item.meta}</div> : null}
        </>
      );

      if (item.onClick) {
        return (
          <button
            key={item.key || index}
            type="button"
            className="nv-insight-item"
            onClick={item.onClick}
          >
            {content}
          </button>
        );
      }

      return (
        <div key={item.key || index} className="nv-insight-item">
          {content}
        </div>
      );
    })}
  </div>
);

export default InsightList;
