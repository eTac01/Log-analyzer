import { motion } from 'framer-motion';
import { Activity, Shield, Database, Clock, FileText, Zap } from 'lucide-react';

const features = [
    {
        icon: Activity,
        title: 'Real-Time Log Analysis',
        description: 'Process millions of log events per second with sub-millisecond latency and instant threat detection.',
    },
    {
        icon: Shield,
        title: 'Threat Severity Classification',
        description: 'AI-powered threat assessment with automatic categorization into Critical, High, Medium, and Low severity levels.',
    },
    {
        icon: Database,
        title: 'IP Reputation & Blacklist Detection',
        description: 'Instant validation against global threat intelligence feeds and real-time blacklist databases.',
    },
    {
        icon: Clock,
        title: 'Timeline-Based Attack Correlation',
        description: 'Visualize attack patterns across time with intelligent event correlation and attack chain reconstruction.',
    },
    {
        icon: FileText,
        title: 'Analyst-Ready Reports',
        description: 'Generate comprehensive incident reports with executive summaries and technical deep-dives.',
    },
    {
        icon: Zap,
        title: 'High-Performance Engine',
        description: 'Built for enterprise-scale operations with distributed processing and zero-downtime updates.',
    },
];

function FeatureShowcase() {
    return (
        <section id="features" className="py-24 px-6 bg-gradient-to-b from-cyber-bg to-cyber-bg-secondary">
            <div className="max-w-7xl mx-auto">
                <motion.div
                    initial={{ opacity: 0, y: 30 }}
                    whileInView={{ opacity: 1, y: 0 }}
                    viewport={{ once: true }}
                    transition={{ duration: 0.6 }}
                    className="text-center mb-16"
                >
                    <h2 className="font-orbitron text-4xl md:text-5xl font-bold text-cyber-text mb-4">
                        Enterprise-Grade Capabilities
                    </h2>
                    <p className="font-inter text-xl text-cyber-muted max-w-2xl mx-auto">
                        Built for the most demanding security operations centers
                    </p>
                </motion.div>

                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                    {features.map((feature, index) => (
                        <motion.div
                            key={index}
                            initial={{ opacity: 0, y: 30 }}
                            whileInView={{ opacity: 1, y: 0 }}
                            viewport={{ once: true }}
                            transition={{ duration: 0.5, delay: index * 0.1 }}
                            whileHover={{ scale: 1.02, y: -5 }}
                            className="group relative bg-gradient-to-br from-cyber-bg-secondary to-cyber-bg-tertiary border border-cyber-primary/20 rounded-xl p-6 backdrop-blur-sm hover:border-cyber-primary/60 transition-all duration-300"
                        >
                            <div className="absolute inset-0 bg-gradient-to-br from-cyber-primary/5 to-transparent rounded-xl opacity-0 group-hover:opacity-100 transition-opacity duration-300" />

                            <div className="relative z-10">
                                <div className="w-14 h-14 rounded-lg bg-cyber-primary/10 flex items-center justify-center mb-4 group-hover:bg-cyber-primary/20 transition-colors duration-300">
                                    <feature.icon className="w-7 h-7 text-cyber-primary" strokeWidth={1.5} />
                                </div>

                                <h3 className="font-orbitron text-xl font-bold text-cyber-text mb-3">
                                    {feature.title}
                                </h3>

                                <p className="font-inter text-cyber-muted leading-relaxed">
                                    {feature.description}
                                </p>

                                <div className="mt-4 w-12 h-0.5 bg-gradient-to-r from-cyber-primary to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-300" />
                            </div>

                            <div className="absolute top-0 right-0 w-20 h-20 bg-cyber-primary/5 rounded-full blur-2xl opacity-0 group-hover:opacity-100 transition-opacity duration-300" />
                        </motion.div>
                    ))}
                </div>
            </div>
        </section>
    );
}

export default FeatureShowcase;
