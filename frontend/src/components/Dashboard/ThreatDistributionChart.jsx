import { Pie } from 'react-chartjs-2';
import { Chart as ChartJS, ArcElement, Tooltip, Legend } from 'chart.js';
import EmptyState from '../V2/EmptyState';

ChartJS.register(ArcElement, Tooltip, Legend);

const ThreatDistributionChart = ({ distribution = {}, height = 180, legendPosition = 'right' }) => {
  const labels = Object.keys(distribution);
  const values = Object.values(distribution);

  if (labels.length === 0) {
    return (
      <div className="nv-chart-shell" style={{ '--nv-chart-height': `${height}px` }}>
        <div className="nv-chart-shell__empty">
          <EmptyState
            icon="ri-pie-chart-line"
            title="No threat data available"
            description="The distribution chart will populate once the threat queue has classified events."
          />
        </div>
      </div>
    );
  }

  const data = {
    labels: labels,
    datasets: [
      {
        data: values,
        backgroundColor: [
          'rgba(0, 255, 157, 0.2)',  // LOW
          'rgba(255, 191, 0, 0.2)',  // MEDIUM
          'rgba(255, 42, 42, 0.2)',  // HIGH
          'rgba(255, 143, 143, 0.5)', // CRITICAL
        ],
        borderColor: [
          '#00ff9d',
          '#ffbf00',
          '#ff2a2a',
          '#ff8f8f',
        ],
        borderWidth: 1,
      },
    ],
  };

  const options = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        position: legendPosition,
        labels: {
          color: '#94a3b8',
          font: { size: 10, weight: 'bold' },
          usePointStyle: true,
          padding: 15,
        },
      },
      tooltip: {
        backgroundColor: 'rgba(15, 23, 42, 0.9)',
        titleColor: '#fff',
        bodyColor: '#cbd5e1',
        borderColor: 'rgba(255, 255, 255, 0.1)',
        borderWidth: 1,
        padding: 10,
        displayColors: true,
      }
    }
  };

  return (
    <div className="nv-chart-shell" style={{ '--nv-chart-height': `${height}px` }}>
      <div className="nv-chart-shell__canvas">
        <Pie data={data} options={options} />
      </div>
    </div>
  );
};

export default ThreatDistributionChart;
