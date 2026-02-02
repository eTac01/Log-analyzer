import { useNavigate } from 'react-router-dom';
import HeroSection from '../components/landing/HeroSection';
import Header from '../components/landing/Header';
import FeatureShowcase from '../components/landing/FeatureShowcase';
import TrustSection from '../components/landing/TrustSection';

function LandingPage() {
    const navigate = useNavigate();

    return (
        <div className="min-h-screen bg-cyber-bg text-cyber-text transition-colors duration-300">
            <Header />
            <HeroSection onLaunch={() => navigate('/dashboard')} />
            <FeatureShowcase />
            <TrustSection />
        </div>
    );
}

export default LandingPage;
