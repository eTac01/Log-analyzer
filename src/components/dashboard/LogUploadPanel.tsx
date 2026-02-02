import { Upload, FileText } from 'lucide-react';

function LogUploadPanel() {
    return (
        <div className="bg-gradient-to-br from-[#0f1535] to-[#0a0e27] border border-cyber-primary/20 rounded-xl p-6">
            <div className="flex items-center gap-2 mb-4">
                <FileText className="w-5 h-5 text-cyber-primary" />
                <h2 className="font-orbitron text-xl font-bold text-cyber-text">Log Analysis</h2>
            </div>

            <div className="border-2 border-dashed border-cyber-primary/30 rounded-lg p-8 text-center hover:border-cyber-primary/60 hover:bg-cyber-primary/5 transition-all duration-300 cursor-pointer group">
                <Upload className="w-12 h-12 text-cyber-primary mx-auto mb-4 group-hover:scale-110 transition-transform" />
                <p className="font-inter text-cyber-text mb-2">Drop log files here or click to browse</p>
                <p className="text-sm text-cyber-muted">Supports .log, .txt, .json, .csv formats</p>
            </div>

            <div className="mt-4 grid grid-cols-3 gap-4">
                <div className="bg-cyber-bg-secondary border border-cyber-primary/10 rounded-lg p-3">
                    <p className="text-xs text-cyber-muted mb-1">Status</p>
                    <p className="font-orbitron text-sm text-cyber-green">Ready</p>
                </div>
                <div className="bg-cyber-bg-secondary border border-cyber-primary/10 rounded-lg p-3">
                    <p className="text-xs text-cyber-muted mb-1">Last Scan</p>
                    <p className="font-orbitron text-sm text-cyber-text">2 min ago</p>
                </div>
                <div className="bg-cyber-bg-secondary border border-cyber-primary/10 rounded-lg p-3">
                    <p className="text-xs text-cyber-muted mb-1">Processed</p>
                    <p className="font-orbitron text-sm text-cyber-text">1.2M logs</p>
                </div>
            </div>
        </div>
    );
}

export default LogUploadPanel;
