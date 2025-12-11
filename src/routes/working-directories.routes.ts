import { Router, Request } from 'express';
import { WorkingDirectoriesResponse, WorkingDirectory } from '@/types/index.js';
import { WorkingDirectoriesService } from '@/services/working-directories-service.js';
import { ProjectService } from '@/services/project-service';
import { createLogger } from '@/services/logger.js';

export function createWorkingDirectoriesRoutes(
  workingDirectoriesService: WorkingDirectoriesService,
  projectService: ProjectService
): Router {
  const router = Router();
  const logger = createLogger('WorkingDirectoriesRoutes');

  // Get all working directories with smart suffixes
  router.get('/', async (req: Request<Record<string, never>, WorkingDirectoriesResponse>, res, next) => {
    const requestId = req.headers['x-request-id'] || 'unknown';
    const username = req.cookies['dss_user_name'];
    if (!username) {
      logger.warn('No username found in cookies', { requestId });
      return res.status(401).json({ error: 'Authentication required' });
    }
    logger.info('Getting working directories', { requestId, username });

    try {
      let result = await workingDirectoriesService.getWorkingDirectories();
      const user_claude_project_path = projectService.getProjectPath(username);
      const user_project = result.directories.find((w: WorkingDirectory) => w.path.includes(user_claude_project_path));

      if (user_project) {
        result = {
          directories: [user_project],
          totalCount: 1
        }
      } else {
        logger.warn(`User ${username} has no working directory, I will create a Claude project ${user_claude_project_path} for him!`, { requestId });
        const project = await projectService.addProjectManually(user_claude_project_path);
        result =  {
          directories: [{
            path: user_claude_project_path,
            shortname: project.displayName,
            lastDate: new Date().toISOString().replace(/\.\d{3}Z$/, 'Z'),
            conversationCount: 0
          }],
          totalCount: 1
        }
      }
      
      logger.debug('Retrieved working directories', {
        requestId,
        totalDirectories: result.totalCount
      });
      
      res.json(result);
    } catch (error) {
      logger.error('Failed to get working directories', error, { requestId });
      next(error);
    }
  });

  return router;
}