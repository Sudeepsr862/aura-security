// ─── People Routes ────────────────────────────────────────────────────────────
// GET /api/people   — list synthetic people and their devices

import { Router } from 'express';
import { requireAuth } from '../middleware/auth.js';

export const peopleRouter = Router();

/**
 * GET /api/people
 * Returns synthetic people with their devices and permitted service count.
 * Names, emails, and devices are entirely fictional.
 */
peopleRouter.get('/', requireAuth, (req, res) => {
  const people = req.db.prepare(
    `SELECT
       p.id,
       p.display_name,
       p.demo_email,
       p.department,
       p.role_title,
       COUNT(DISTINCT d.id) as device_count,
       COUNT(DISTINCT ps.service_id) as permitted_service_count
     FROM synthetic_people p
     LEFT JOIN synthetic_devices d ON d.person_id = p.id
     LEFT JOIN person_permitted_services ps ON ps.person_id = p.id
     WHERE p.is_demo = 1
     GROUP BY p.id
     ORDER BY p.display_name`
  ).all() as {
    id: number; display_name: string; demo_email: string;
    department: string; role_title: string;
    device_count: number; permitted_service_count: number;
  }[];

  return res.json({
    people,
    demoNote: 'All names, email addresses, and devices are entirely fictional synthetic records.',
  });
});
