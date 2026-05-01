import { Line } from 'react-chartjs-2';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Legend,
  Filler,
} from 'chart.js';
import EmptyState from '../V2/EmptyState';

ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Legend,
  Filler
);

const TrafficChart = ({ data, height = 240 }) => {
  const labels = data?.labels || [];
  const values = data?.values || [];

  if (labels.length === 0 || values.length === 0) {
    return (
      <div className="nv-chart-shell" style={{ '--nv-chart-height': `${height}px` }}>
        <div className="nv-chart-shell__empty">
          <EmptyState
            icon="ri-line-chart-line"
            title="No traffic data yet"
            description="The chart will populate once the live flow window has enough samples."
          />
        </div>
      </div>
    );
  }

  const chartData = {
    labels,
    datasets: [
      {
        label: 'Traffic (MB)',
        data: values,
        borderColor: '#06b6d4',
        backgroundColor: (context) => {
          const ctx = context.chart.ctx;
          const gradient = ctx.createLinearGradient(0, 0, 0, 400);
          gradient.addColorStop(0, "rgba(6, 182, 212, 0.5)");
          gradient.addColorStop(1, "rgba(6, 182, 212, 0)");
          return gradient;
        },
        fill: true,
        tension: 0.35,
        borderWidth: 2,
        pointRadius: values.length <= 8 ? 3 : 2,
        pointHoverRadius: 4,
        pointBackgroundColor: '#22d3ee',
      },
    ],
  };

  const options = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: { legend: { display: false } },
    interaction: {
      intersect: false,
      mode: 'index',
    },
    scales: {
      y: {
        beginAtZero: true,
        grid: { color: "rgba(255, 255, 255, 0.05)" },
        ticks: { color: "#94a3b8", maxTicksLimit: 5 },
      },
      x: {
        grid: { display: false },
        ticks: { color: "#94a3b8", maxTicksLimit: 8 },
      },
    },
  };

  return (
    <div className="nv-chart-shell" style={{ '--nv-chart-height': `${height}px` }}>
      <div className="nv-chart-shell__canvas">
        <Line data={chartData} options={options} />
      </div>
    </div>
  );
};

export default TrafficChart;
