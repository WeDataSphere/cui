/**
 * PROJECT DISCOVERY AND MANAGEMENT SYSTEM
 * ========================================
 * 
 * This module manages project discovery for both Claude CLI.
 * 
 * ## Architecture Overview
 * 
 * 1. **Claude Projects** (stored in ~/.claude/projects/)
 *    - Each project is a directory named with the project path encoded (/ replaced with -)
 *    - Contains .jsonl files with conversation history including 'cwd' field
 *    - Project metadata stored in ~/.claude/project-config.json
 * 
 * ## Project Discovery Strategy
 * 
 * 1. **Claude Projects Discovery**:
 *    - Scan ~/.claude/projects/ directory for Claude project folders
 *    - Extract actual project path from .jsonl files (cwd field)
 *    - Fall back to decoded directory name if no sessions exist
 * 
 * 3. **Manual Project Addition**:
 *    - Users can manually add project paths via UI
 *    - Stored in ~/.claude/project-config.json with 'manuallyAdded' flag
 *    - Allows discovering Cursor sessions for projects without Claude sessions
 * 
 * ## Critical Limitations
 * 
 * - **CANNOT discover Cursor-only projects**: From a quick check, there was no mention of
 *   the cwd of each project. if someone has the time, you can try to reverse engineer it.
 * 
 * - **Project relocation breaks history**: If a project directory is moved or renamed,
 *   the MD5 hash changes, making old Cursor sessions inaccessible unless the old
 *   path is known and manually added.
 * 
 * ## Error Handling
 * 
 * - Missing ~/.claude directory is handled gracefully with automatic creation
 * - ENOENT errors are caught and handled without crashing
 * - Empty arrays returned when no projects/sessions exist
 * 
 * ## Caching Strategy
 * 
 * - Project directory extraction is cached to minimize file I/O
 * - Cache is cleared when project configuration changes
 */

import { promises as fs } from 'fs';
import fsSync from 'fs';
import path from 'path';
import readline from 'readline';
import { createLogger } from '@/services/logger.js';
import { type Logger } from './logger.js';

interface ProjectConfig {
  displayName?: string;
  manuallyAdded?: boolean;
  originalPath?: string;
}

type ProjectConfigMap = Record<string, ProjectConfig>;

export class ProjectService {

  private logger: Logger;
  // Cache for extracted project directories
  private projectDirectoryCache: Map<string, string>;

  constructor(){
    this.logger = createLogger('FileSystemService');
    this.projectDirectoryCache = new Map();
  }

  // Clear cache when needed (called when project files change)
  clearProjectDirectoryCache() {
    this.projectDirectoryCache.clear();
  }

  getUserProjectPath(projectName: string): string {
    const projectDir = path.join('/mnt/bdap', projectName);
    return projectDir
  }

  // Load project configuration file
  async loadProjectConfig(): Promise<ProjectConfigMap> {
    const configPath = path.join(process.env.HOME, '.claude', 'project-config.json');
    try {
      const configData = await fs.readFile(configPath, 'utf8');
      return JSON.parse(configData);
    } catch (error) {
      // Return empty config if file doesn't exist
      return {};
    }
  }

  // Save project configuration file
  async saveProjectConfig(config: ProjectConfigMap) {
    const claudeDir = path.join(process.env.HOME, '.claude');
    const configPath = path.join(claudeDir, 'project-config.json');
    
    // Ensure the .claude directory exists
    try {
      await fs.mkdir(claudeDir, { recursive: true });
    } catch (error) {
      if (error instanceof Error && 'code' in error && error.code !== 'EEXIST') {
        throw error;
      }
    }
    
    await fs.writeFile(configPath, JSON.stringify(config, null, 2), 'utf8');
  }

  // Generate better display name from path
  async generateDisplayName(projectName: string, actualProjectDir: string | null = null) {
    // Use actual project directory if provided, otherwise decode from project name
    let projectPath = actualProjectDir || projectName.replace(/-/g, '/');
    
    // Try to read package.json from the project path
    try {
      const packageJsonPath = path.join(projectPath, 'package.json');
      const packageData = await fs.readFile(packageJsonPath, 'utf8');
      const packageJson = JSON.parse(packageData);
      
      // Return the name from package.json if it exists
      if (packageJson.name) {
        return packageJson.name;
      }
    } catch (error) {
      // Fall back to path-based naming if package.json doesn't exist or can't be read
    }
    
    // If it starts with /, it's an absolute path
    if (projectPath.startsWith('/')) {
      const parts = projectPath.split('/').filter(Boolean);
      // Return only the last folder name
      return parts[parts.length - 1] || projectPath;
    }
    
    return projectPath;
  }

  // Extract the actual project directory from JSONL sessions (with caching)
  async extractProjectDirectory(projectName: string) {
    // Check cache first
    if (this.projectDirectoryCache.has(projectName)) {
      return this.projectDirectoryCache.get(projectName);
    }
    
    
    const projectDir = path.join(process.env.HOME, '.claude', 'projects', projectName);
    const cwdCounts = new Map();
    let latestTimestamp = 0;
    let latestCwd = null;
    let extractedPath;
    
    try {
      // Check if the project directory exists
      await fs.access(projectDir);
      
      const files = await fs.readdir(projectDir);
      const jsonlFiles = files.filter((file: string) => file.endsWith('.jsonl'));
      
      if (jsonlFiles.length === 0) {
        // Fall back to decoded project name if no sessions
        extractedPath = projectName.replace(/-/g, '/');
      } else {
        // Process all JSONL files to collect cwd values
        for (const file of jsonlFiles) {
          const jsonlFile = path.join(projectDir, file);
          const fileStream = fsSync.createReadStream(jsonlFile);
          const rl = readline.createInterface({
            input: fileStream,
            crlfDelay: Infinity
          });
          
          for await (const line of rl) {
            if (line.trim()) {
              try {
                const entry = JSON.parse(line);
                
                if (entry.cwd) {
                  // Count occurrences of each cwd
                  cwdCounts.set(entry.cwd, (cwdCounts.get(entry.cwd) || 0) + 1);
                  
                  // Track the most recent cwd
                  const timestamp = new Date(entry.timestamp || 0).getTime();
                  if (timestamp > latestTimestamp) {
                    latestTimestamp = timestamp;
                    latestCwd = entry.cwd;
                  }
                }
              } catch (parseError) {
                // Skip malformed lines
              }
            }
          }
        }
        
        // Determine the best cwd to use
        if (cwdCounts.size === 0) {
          // No cwd found, fall back to decoded project name
          extractedPath = projectName.replace(/-/g, '/');
        } else if (cwdCounts.size === 1) {
          // Only one cwd, use it
          extractedPath = Array.from(cwdCounts.keys())[0];
        } else {
          // Multiple cwd values - prefer the most recent one if it has reasonable usage
          const mostRecentCount = cwdCounts.get(latestCwd) || 0;
          const maxCount = Math.max(...cwdCounts.values());
          
          // Use most recent if it has at least 25% of the max count
          if (mostRecentCount >= maxCount * 0.25) {
            extractedPath = latestCwd;
          } else {
            // Otherwise use the most frequently used cwd
            for (const [cwd, count] of cwdCounts.entries()) {
              if (count === maxCount) {
                extractedPath = cwd;
                break;
              }
            }
          }
          
          // Fallback (shouldn't reach here)
          if (!extractedPath) {
            extractedPath = latestCwd || projectName.replace(/-/g, '/');
          }
        }
      }
      
      // Cache the result
      this.projectDirectoryCache.set(projectName, extractedPath);
      
      return extractedPath;
      
    } catch (error) {
      // If the directory doesn't exist, just use the decoded project name
      if (error instanceof Error && 'code' in error && error.code === 'ENOENT') {
        extractedPath = projectName.replace(/-/g, '/');
      } else {
        console.error(`Error extracting project directory for ${projectName}:`, error);
        // Fall back to decoded project name for other errors
        extractedPath = projectName.replace(/-/g, '/');
      }
      
      // Cache the fallback result too
      this.projectDirectoryCache.set(projectName, extractedPath);
      
      return extractedPath;
    }
  }

  async getProjects() {
    const claudeDir = path.join(process.env.HOME, '.claude', 'projects');
    const config = await this.loadProjectConfig();
    const projects = [];
    const existingProjects = new Set();
    
    try {
      // Check if the .claude/projects directory exists
      await fs.access(claudeDir);
      
      // First, get existing Claude projects from the file system
      const entries = await fs.readdir(claudeDir, { withFileTypes: true });
      
      for (const entry of entries) {
        if (entry.isDirectory()) {
          existingProjects.add(entry.name);
          const projectPath = path.join(claudeDir, entry.name);
          
          // Extract actual project directory from JSONL sessions
          const actualProjectDir = await this.extractProjectDirectory(entry.name);
          
          // Get display name from config or generate one
          const customName = config[entry.name]?.displayName;
          const autoDisplayName = await this.generateDisplayName(entry.name, actualProjectDir);
          const fullPath = actualProjectDir;
          
          const project = {
            name: entry.name,
            path: actualProjectDir,
            displayName: customName || autoDisplayName,
            fullPath: fullPath,
            isCustomName: !!customName,
            sessions: []
          };
          
          projects.push(project);
        }
      }
    } catch (error) {
      // If the directory doesn't exist (ENOENT), that's okay - just continue with empty projects
      if (!(error instanceof Error && 'code' in error && error.code === 'ENOENT')) {
        console.error('Error reading projects directory:', error);
      }
    }
    
    // Add manually configured projects that don't exist as folders yet
    for (const [projectName, projectConfig] of Object.entries(config)) {
      if (!existingProjects.has(projectName) && projectConfig.manuallyAdded) {
        // Use the original path if available, otherwise extract from potential sessions
        let actualProjectDir = projectConfig.originalPath;
        
        if (!actualProjectDir) {
          try {
            actualProjectDir = await this.extractProjectDirectory(projectName);
          } catch (error) {
            // Fall back to decoded project name
            actualProjectDir = projectName.replace(/-/g, '/');
          }
        }
        
          const project = {
            name: projectName,
            path: actualProjectDir,
            displayName: projectConfig.displayName || await this.generateDisplayName(projectName, actualProjectDir || null),
            fullPath: actualProjectDir,
            isCustomName: !!projectConfig.displayName,
            isManuallyAdded: true
          };
        
        projects.push(project);
      }
    }
    
    return projects;
  }

  // Rename a project's display name
  async renameProject(projectName: string, newDisplayName: string) {
    const config = await this.loadProjectConfig();
    
    if (!newDisplayName || newDisplayName.trim() === '') {
      // Remove custom name if empty, will fall back to auto-generated
      delete config[projectName];
    } else {
      // Set custom display name
      config[projectName] = {
        displayName: newDisplayName.trim()
      };
    }
    
    await this.saveProjectConfig(config);
    return true;
  }


  // Delete an empty project
  async deleteProject(projectName: string) {
    const projectDir = path.join(process.env.HOME, '.claude', 'projects', projectName);
    
    try {
      // Remove the project directory
      await fs.rm(projectDir, { recursive: true, force: true });
      
      // Remove from project config
      const config = await this.loadProjectConfig();
      delete config[projectName];
      await this.saveProjectConfig(config);
      
      return true;
    } catch (error) {
      console.error(`Error deleting project ${projectName}:`, error);
      throw error;
    }
  }

  // Add a project manually to the config (without creating folders)
  async addProjectManually(projectPath: string, displayName = null) {
    const absolutePath = path.resolve(projectPath);
    
    try {
      // Check if the path exists
      await fs.access(absolutePath);
    } catch (error) {
      // Create the directory
      await fs.mkdir(absolutePath, { recursive: true });
    }
    
    // Generate project name (encode path for use as directory name)
    const projectName = absolutePath.replace(/\//g, '-');
    
    // Check if project already exists in config
    const config = await this.loadProjectConfig();
    const projectDir = path.join(process.env.HOME, '.claude', 'projects', projectName);

    if (config[projectName]) {
      throw new Error(`Project already configured for path: ${absolutePath}`);
    }

    // Allow adding projects even if the directory exists - this enables tracking
    // existing Claude Code or Cursor projects in the UI
    
    // Add to config as manually added project
    config[projectName] = {
      manuallyAdded: true,
      originalPath: absolutePath
    };
    
    if (displayName) {
      config[projectName].displayName = displayName;
    }
    
    await this.saveProjectConfig(config);
    
    
    return {
      name: projectName,
      path: absolutePath,
      fullPath: absolutePath,
      displayName: displayName || await this.generateDisplayName(projectName, absolutePath),
      isManuallyAdded: true,
      sessions: [],
      cursorSessions: []
    };
  }

}