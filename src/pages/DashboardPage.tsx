import { useState } from 'react';
import Sidebar from '../components/dashboard/Sidebar';
import TopBar from '../components/dashboard/TopBar';
import LogUploadPanel from '../components/dashboard/LogUploadPanel';
import ThreatCards from '../components/dashboard/ThreatCards';
import AnalyticsPanel from '../components/dashboard/AnalyticsPanel';
import IPIntelligencePanel from '../components/dashboard/IPIntelligencePanel';

function DashboardPage() {
    const [activeView, setActiveView] = useState('dashboard');

    return (
        <div className="min-h-screen bg-[#0a0e27] text-[#eaeaea] flex">
            <Sidebar activeView={activeView} setActiveView={setActiveView} />

            <div className="flex-1 flex flex-col">
                <TopBar />

                <main className="flex-1 p-6 overflow-y-auto">
                    {activeView === 'dashboard' && (
                        <div className="grid grid-cols-12 gap-6">
                            <div className="col-span-12">
                                <LogUploadPanel />
                            </div>

                            <div className="col-span-12 lg:col-span-8">
                                <ThreatCards />
                            </div>

                            <div className="col-span-12 lg:col-span-4">
                                <IPIntelligencePanel />
                            </div>

                            <div className="col-span-12">
                                <AnalyticsPanel />
                            </div>
                        </div>
                    )}
                </main>
            </div>
        </div>
    );
}

export default DashboardPage;
