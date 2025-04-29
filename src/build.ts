import { promises as fs } from 'fs';
import { join } from 'path';

const buildFolder = "./build";
const rootFolder = ".";

async function copyPath(...srcs: Array<string>) {
    if (srcs.length < 2) throw new Error("Too few arguments!");
    const dest = srcs.pop()!;
    await fs.mkdir(dest, { recursive: true });
    for (const src of srcs) {
        const entries = await fs.readdir(src, { withFileTypes: true });

        for (const entry of entries) {
            if (!entry.name.includes("build") && !entry.name.includes("test.d.ts")) {
                const srcPath = join(src, entry.name);
                const destPath = join(dest, entry.name);


                if (entry.isDirectory()) {
                    await copyPath(srcPath, destPath); // Ricorsivo per le sottocartelle
                } else {
                    await fs.copyFile(srcPath, destPath); // Copia file
                }
            }
        }
    }
}

async function deletePath(paths: string | Array<string>) {
    if (!Array.isArray(paths)) paths = [paths];
    for (const path of paths)
        await fs.rm(path, { recursive: true, force: true });
}

const logError = (error: any) => console.error('Errore:', error)

copyPath(buildFolder, rootFolder)
    .then(() =>
        deletePath(buildFolder)
            .then(() => console.log('Builded!\n'))
            .catch(logError))
    .catch(logError);