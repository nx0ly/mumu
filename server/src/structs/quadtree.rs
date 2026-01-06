// implementation of a quad tree for collision resolution.
// see: https://en.wikipedia.org/wiki/Quadtree

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub struct Point {
    pub x: f32,
    pub y: f32,
}

impl Point {
    #[inline]
    pub fn new(x: f32, y: f32) -> Self {
        Self { x, y }
    }

    #[inline]
    pub fn dist(x1: f32, y1: f32, x2: f32, y2: f32) -> f32 {
        // using squared distance
        (x2 - x1).powf(2.) + (y2 - y1).powf(2.)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Rect {
    pub x: f32,
    pub y: f32,
    pub width: f32,
    pub height: f32,
}

impl Rect {
    #[inline]
    pub fn new(x: f32, y: f32, width: f32, height: f32) -> Self {
        Self {
            x,
            y,
            width,
            height,
        }
    }

    pub fn has_point(&self, point: Point) -> bool {
        point.x >= self.x - self.width
            && point.x <= self.x + self.width
            && point.y >= self.y - self.height
            && point.y <= self.y + self.height
    }

    pub fn intersects_rect(&self, rect: &Rect) -> bool {
        return !(rect.x - rect.width > self.x + self.width
            || rect.x + rect.width < self.x - self.width
            || rect.y - rect.height > self.y + self.height
            || rect.y + rect.height < self.y - self.height);
    }
}

#[derive(Debug, Clone)]
pub struct Quadtree {
    boundary: Rect,
    capacity: usize,
    points: Vec<Point>,
    divided: bool,
    top_left: Option<Box<Quadtree>>,
    top_right: Option<Box<Quadtree>>,
    bottom_left: Option<Box<Quadtree>>,
    bottom_right: Option<Box<Quadtree>>,
}

impl Quadtree {
    #[inline]
    pub fn new(boundary: Rect, capacity: usize) -> Self {
        Self {
            boundary,
            capacity,
            points: Vec::new(),
            divided: false,
            top_left: None,
            top_right: None,
            bottom_left: None,
            bottom_right: None,
        }
    }

    // return false if it already contains the point.
    pub fn insert(&mut self, point: &Point) -> bool {
        if !self.boundary.has_point(*point) {
            return false;
        }

        if self.points.len() < self.capacity {
            self.points.push(*point);
            return true;
        } else {
            if !self.divided {
                self.subdivide();
            }

            if self.top_right.as_mut().unwrap().insert(point) {
                return true;
            }
            if self.top_left.as_mut().unwrap().insert(point) {
                return true;
            }
            if self.bottom_right.as_mut().unwrap().insert(point) {
                return true;
            }
            if self.bottom_left.as_mut().unwrap().insert(point) {
                return true;
            }

            return false;
        }
    }

    fn subdivide(&mut self) {
        // if exceeds capacity of a quad, divide into smaller quads.
        let top_right = Rect::new(
            self.boundary.x + self.boundary.width / 2.,
            self.boundary.y - self.boundary.height / 2.,
            self.boundary.width / 2.,
            self.boundary.height / 2.,
        );
        let top_left = Rect::new(
            self.boundary.x - self.boundary.width / 2.,
            self.boundary.y - self.boundary.height / 2.,
            self.boundary.width / 2.,
            self.boundary.height / 2.,
        );
        let bottom_right = Rect::new(
            self.boundary.x + self.boundary.width / 2.,
            self.boundary.y + self.boundary.height / 2.,
            self.boundary.width / 2.,
            self.boundary.height / 2.,
        );
        let bottom_left = Rect::new(
            self.boundary.x - self.boundary.width / 2.,
            self.boundary.y - self.boundary.height / 2.,
            self.boundary.width / 2.,
            self.boundary.height / 2.,
        );

        self.top_right = Some(Box::new(Quadtree::new(top_right, self.capacity)));
        self.top_left = Some(Box::new(Quadtree::new(top_left, self.capacity)));
        self.bottom_right = Some(Box::new(Quadtree::new(bottom_right, self.capacity)));
        self.bottom_left = Some(Box::new(Quadtree::new(bottom_left, self.capacity)));

        self.divided = true;
    }

    pub fn get_points_within_rect(&self, rect: Rect) -> Vec<Point> {
        let mut points: Vec<Point> = Vec::new();

        // check if the rectangle lies within the bound of the quad tree.
        if !self.boundary.intersects_rect(&rect) {
            return points;
        } else {
            self.points.iter().for_each(|point| {
                if rect.has_point(*point) {
                    points.push(*point);
                }
            });

            if self.divided {
                let top_left_points = self.top_left.as_ref().unwrap().get_points_within_rect(rect);
                let top_right_points = self
                    .top_right
                    .as_ref()
                    .unwrap()
                    .get_points_within_rect(rect);
                let bottom_left_points = self
                    .bottom_left
                    .as_ref()
                    .unwrap()
                    .get_points_within_rect(rect);
                let bottom_right_points = self
                    .bottom_right
                    .as_ref()
                    .unwrap()
                    .get_points_within_rect(rect);

                points.extend(top_left_points);
                points.extend(top_right_points);
                points.extend(bottom_left_points);
                points.extend(bottom_right_points);
            }
        }

        points
    }

    pub fn get_points_within_circle(&self, x: f32, y: f32, rad: f32) -> Vec<Point> {
        // i'm using the same strategy here as used in the 'quadtree-simple' crate.
        // use a rect with same size to query for points
        // then filter those to the radius of the circle.

        let rect = Rect::new(x, y, rad, rad);
        let mut temp = self.get_points_within_rect(rect);
        temp.retain(|point| {
            let dist = Point::dist(point.x, point.y, x, y);
            if dist < rad.powf(2.) {
                true
            } else {
                false
            }
        });

        temp
    }
}
