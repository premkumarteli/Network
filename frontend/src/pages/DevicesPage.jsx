import React, { useState, useEffect } from 'react';
import axios from 'axios';
import DeviceTable from '../components/Devices/DeviceTable';

const DevicesPage = () => {
    const [devices, setDevices] = useState([]);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        fetchDevices();
    }, []);

    const fetchDevices = async () => {
        try {
            const res = await axios.get('/api/devices');
            setDevices(res.data);
            setLoading(false);
        } catch (err) {
            console.error("Failed to fetch devices", err);
            setLoading(false);
        }
    };

    return (
        <div className="animate-fade">
            <div className="header">
                <h2>Network Devices</h2>
                <div style={{ display: 'flex', gap: '1rem' }}>
                    <button className="action-btn" onClick={fetchDevices}>
                        <i className="ri-refresh-line"></i> Refresh
                    </button>
                </div>
            </div>
            
            {loading ? (
                <div className="loading-state">Loading inventory...</div>
            ) : (
                <DeviceTable devices={devices} />
            )}
        </div>
    );
};

export default DevicesPage;
