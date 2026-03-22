import { motion } from 'framer-motion';
import AnimatedCounter from './AnimatedCounter';

const KpiCard = ({
  icon,
  label,
  value,
  meta,
  tone = 'default',
  onClick,
  valueFormatter,
  accent,
}) => {
  const interactive = typeof onClick === 'function';

  return (
    <motion.button
      type="button"
      className={`kpi-card ${tone} ${interactive ? 'interactive' : ''}`.trim()}
      onClick={onClick}
      whileHover={{ y: -4, scale: 1.01 }}
      whileTap={{ scale: 0.99 }}
      transition={{ type: 'spring', stiffness: 260, damping: 22 }}
      style={accent ? { '--kpi-accent': accent } : undefined}
    >
      <div className="kpi-card__header">
        <span className="kpi-card__icon">
          <i className={icon}></i>
        </span>
        <span className="kpi-card__label">{label}</span>
      </div>
      <div className="kpi-card__value">
        <AnimatedCounter value={value} formatter={valueFormatter} />
      </div>
      <div className="kpi-card__meta">{meta}</div>
      {interactive ? (
        <span className="kpi-card__action">
          Open
          <i className="ri-arrow-right-up-line"></i>
        </span>
      ) : null}
    </motion.button>
  );
};

export default KpiCard;
