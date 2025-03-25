const fs = require('fs');
const path = require('path');
const archiver = require('archiver');

// Get version from environment variable
const version = process.env.VERSION || '1.0.0';

// Create dist directory if it doesn't exist
const distDir = path.join(__dirname, '..', 'dist');
if (!fs.existsSync(distDir)) {
    fs.mkdirSync(distDir);
}

// Create a write stream for the zip file
const output = fs.createWriteStream(
    path.join(distDir, `bitbadges-wp-plugin-${version}.zip`)
);
const archive = archiver('zip', {
    zlib: { level: 9 }, // Maximum compression
});

// Listen for all archive data to be written
output.on('close', () => {
    console.log(`Archive created successfully: ${archive.pointer()} bytes`);
});

// Handle errors
archive.on('error', (err) => {
    throw err;
});

// Pipe archive data to the output file
archive.pipe(output);

// Add files to the archive
const rootDir = path.join(__dirname, '../wordpress-plugin');
const excludeDirs = ['node_modules', '.git', 'dist', 'scripts'];
const excludeFiles = [
    'package.json',
    'package-lock.json',
    '.gitignore',
    'README.md',
    'docker-compose.yml',
    'manage.sh',
];

function addFiles(dir) {
    const files = fs.readdirSync(dir);

    files.forEach((file) => {
        const filePath = path.join(dir, file);
        const relativePath = path.relative(rootDir, filePath);

        // Skip excluded directories and files
        if (excludeDirs.includes(file) || excludeFiles.includes(file)) {
            return;
        }

        const stat = fs.statSync(filePath);
        if (stat.isDirectory()) {
            addFiles(filePath);
        } else {
            archive.file(filePath, { name: relativePath });
        }
    });
}

// Start adding files
addFiles(rootDir);

// Finalize the archive
archive.finalize();
