import fetch from 'node-fetch';

export async function getPublicIP(ip) {
    // Handle local development addresses
    if (ip === '::1' || ip === '127.0.0.1') {
        try {
            const response = await fetch('https://api.ipify.org?format=json');
            const data = await response.json();
            return data.ip;
        } catch (error) {
            console.error('Error getting public IP:', error);
            return ip;
        }
    }
    
    // Extract IP from proxy headers if present
    if (ip.includes(',')) {
        return ip.split(',')[0].trim();
    }
    
    return ip;
}

export async function getIPDetails(ip) {
    try {
        // First get the real public IP if we're local
        const publicIP = await getPublicIP(ip);
        
        // Use a more robust error handling approach for the IPify API
        const response = await fetch(`https://geo.ipify.org/api/v2/country,city,vpn?apiKey=at_1p1YAU2cUpp1IOMQKZ5zVrH5JuYZE&ipAddress=${publicIP}`);
        
        if (!response.ok) {
            throw new Error(`IPify API error: ${response.status}`);
        }

        const data = await response.json();
        
        return {
            ip: publicIP,
            country: data.location?.country || 'Unknown',
            city: data.location?.city || 'Unknown',
            region: data.location?.region || 'Unknown',
            isp: data.isp || 'Unknown',
            isVPN: data?.proxy?.vpn || false,
            isProxy: data?.proxy?.proxy || false,
            isTor: data?.proxy?.tor || false
        };
    } catch (error) {
        console.error('Error getting IP details:', error);
        // Provide more informative fallback data
        return {
            ip: ip,
            country: 'Unknown',
            city: 'Unknown',
            region: 'Unknown',
            isp: 'Unknown',
            isVPN: false,
            isProxy: false,
            isTor: false,
            error: error.message
        };
    }
}

// Add helper function to validate IP addresses
export function isValidIP(ip) {
    const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
    const ipv6Regex = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/;
    
    return ipv4Regex.test(ip) || ipv6Regex.test(ip);
}