import fs from 'fs';
import { join } from 'path';

export function scanPages(pagesDir) {
    try {
        console.log('Scanning directory:', pagesDir);
        const files = fs.readdirSync(pagesDir);
        console.log('Found files:', files);
        
        const pages = files
            .filter(file => file.endsWith('.html'))
            .map(file => ({
                id: file,
                name: file.replace('.html', '').split('-').map(
                    word => word.charAt(0).toUpperCase() + word.slice(1)
                ).join(' ')
            }));
            
        console.log('Available pages:', pages);
        return pages;
    } catch (error) {
        console.error('Error scanning pages directory:', error);
        return [];
    }
}