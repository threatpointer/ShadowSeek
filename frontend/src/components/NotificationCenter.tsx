import React, { useState, useEffect } from 'react';
import {
  Badge,
  IconButton,
  Popover,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  Typography,
  Box,
  Divider,
  Button,
  Chip,
} from '@mui/material';
import {
  Notifications,
  CheckCircle,
  Error,
  Info,
  Warning,
  Clear,
  ClearAll,
} from '@mui/icons-material';
import { taskManager } from '../utils/taskManager';

export interface NotificationItem {
  id: string;
  type: 'success' | 'error' | 'info' | 'warning';
  title: string;
  message: string;
  timestamp: number;
  persistent: boolean;
  taskId?: string;
  read: boolean;
}

class NotificationManager {
  private static instance: NotificationManager;
  private notifications: NotificationItem[] = [];
  private listeners: ((notifications: NotificationItem[]) => void)[] = [];
  private readonly STORAGE_KEY = 'shadowseek_notifications';
  private readonly MAX_NOTIFICATIONS = 50;

  private constructor() {
    this.loadFromStorage();
  }

  public static getInstance(): NotificationManager {
    if (!NotificationManager.instance) {
      NotificationManager.instance = new NotificationManager();
    }
    return NotificationManager.instance;
  }

  public addNotification(notification: Omit<NotificationItem, 'id' | 'timestamp' | 'read'>): void {
    const newNotification: NotificationItem = {
      ...notification,
      id: Date.now().toString() + Math.random().toString(36).substr(2, 9),
      timestamp: Date.now(),
      read: false,
    };

    this.notifications.unshift(newNotification);
    
    // Keep only the latest notifications
    if (this.notifications.length > this.MAX_NOTIFICATIONS) {
      this.notifications = this.notifications.slice(0, this.MAX_NOTIFICATIONS);
    }

    this.saveToStorage();
    this.notifyListeners();
  }

  public markAsRead(id: string): void {
    const notification = this.notifications.find(n => n.id === id);
    if (notification) {
      notification.read = true;
      this.saveToStorage();
      this.notifyListeners();
    }
  }

  public markAllAsRead(): void {
    this.notifications.forEach(n => n.read = true);
    this.saveToStorage();
    this.notifyListeners();
  }

  public removeNotification(id: string): void {
    this.notifications = this.notifications.filter(n => n.id !== id);
    this.saveToStorage();
    this.notifyListeners();
  }

  public clearAll(): void {
    this.notifications = [];
    this.saveToStorage();
    this.notifyListeners();
  }

  public getNotifications(): NotificationItem[] {
    return this.notifications;
  }

  public getUnreadCount(): number {
    return this.notifications.filter(n => !n.read).length;
  }

  public subscribe(listener: (notifications: NotificationItem[]) => void): () => void {
    this.listeners.push(listener);
    listener(this.notifications);
    
    return () => {
      const index = this.listeners.indexOf(listener);
      if (index > -1) {
        this.listeners.splice(index, 1);
      }
    };
  }

  private notifyListeners(): void {
    this.listeners.forEach(listener => {
      try {
        listener(this.notifications);
      } catch (error) {
        console.error('Error in notification listener:', error);
      }
    });
  }

  private loadFromStorage(): void {
    try {
      const stored = localStorage.getItem(this.STORAGE_KEY);
      if (stored) {
        this.notifications = JSON.parse(stored);
      }
    } catch (error) {
      console.error('Error loading notifications from storage:', error);
      this.notifications = [];
    }
  }

  private saveToStorage(): void {
    try {
      localStorage.setItem(this.STORAGE_KEY, JSON.stringify(this.notifications));
    } catch (error) {
      console.error('Error saving notifications to storage:', error);
    }
  }
}

export const notificationManager = NotificationManager.getInstance();

const NotificationCenter: React.FC = () => {
  const [notifications, setNotifications] = useState<NotificationItem[]>([]);
  const [anchorEl, setAnchorEl] = useState<HTMLButtonElement | null>(null);
  const [unreadCount, setUnreadCount] = useState(0);
  const [activeTaskCount, setActiveTaskCount] = useState(0);

  useEffect(() => {
    const unsubscribe = notificationManager.subscribe((notifications) => {
      setNotifications(notifications);
      setUnreadCount(notificationManager.getUnreadCount());
    });

    // Subscribe to active task updates
    const taskUnsubscribe = taskManager.onTasksUpdate((tasks) => {
      setActiveTaskCount(tasks.length);
    });

    return () => {
      unsubscribe();
      taskUnsubscribe();
    };
  }, []);

  const handleClick = (event: React.MouseEvent<HTMLButtonElement>) => {
    setAnchorEl(event.currentTarget);
  };

  const handleClose = () => {
    setAnchorEl(null);
  };

  const open = Boolean(anchorEl);

  const getIcon = (type: NotificationItem['type']) => {
    switch (type) {
      case 'success':
        return <CheckCircle sx={{ color: '#4caf50' }} />;
      case 'error':
        return <Error sx={{ color: '#f44336' }} />;
      case 'warning':
        return <Warning sx={{ color: '#ff9800' }} />;
      default:
        return <Info sx={{ color: '#2196f3' }} />;
    }
  };

  const formatTime = (timestamp: number) => {
    const date = new Date(timestamp);
    const now = new Date();
    const diffInHours = (now.getTime() - date.getTime()) / (1000 * 60 * 60);

    if (diffInHours < 1) {
      const diffInMinutes = Math.floor(diffInHours * 60);
      return diffInMinutes < 1 ? 'Just now' : `${diffInMinutes}m ago`;
    }

    if (diffInHours < 24) {
      return `${Math.floor(diffInHours)}h ago`;
    }

    return date.toLocaleDateString();
  };

  const handleNotificationClick = (notification: NotificationItem) => {
    if (!notification.read) {
      notificationManager.markAsRead(notification.id);
    }
  };

  return (
    <>
             <IconButton
         color="inherit"
         onClick={handleClick}
         sx={{ 
           position: 'relative',
           '&:hover': { backgroundColor: 'rgba(255, 255, 255, 0.08)' }
         }}
       >
         <Badge 
           badgeContent={unreadCount + activeTaskCount} 
           color={activeTaskCount > 0 ? "warning" : "error"}
           max={99}
           sx={{
             '& .MuiBadge-badge': {
               backgroundColor: activeTaskCount > 0 ? '#ff9800' : '#f44336',
               color: '#fff',
               animation: activeTaskCount > 0 ? 'pulse 2s infinite' : 'none',
             }
           }}
         >
           <Notifications sx={{ 
             color: activeTaskCount > 0 ? '#ff9800' : 'inherit',
             animation: activeTaskCount > 0 ? 'pulse 2s infinite' : 'none'
           }} />
         </Badge>
       </IconButton>

      <Popover
        open={open}
        anchorEl={anchorEl}
        onClose={handleClose}
        anchorOrigin={{
          vertical: 'bottom',
          horizontal: 'right',
        }}
        transformOrigin={{
          vertical: 'top',
          horizontal: 'right',
        }}
        PaperProps={{
          sx: {
            backgroundColor: '#1e1e1e',
            border: '1px solid #333',
            maxWidth: 400,
            maxHeight: 500,
            minWidth: 350,
          }
        }}
      >
                 <Box sx={{ p: 2, borderBottom: '1px solid #333' }}>
           <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
             <Box>
               <Typography variant="h6" sx={{ color: 'white' }}>
                 Notifications
               </Typography>
               {activeTaskCount > 0 && (
                 <Typography variant="caption" sx={{ color: '#ff9800', display: 'block' }}>
                   {activeTaskCount} active background task{activeTaskCount !== 1 ? 's' : ''}
                 </Typography>
               )}
             </Box>
            <Box sx={{ display: 'flex', gap: 1 }}>
              {unreadCount > 0 && (
                <Button
                  size="small"
                  onClick={() => notificationManager.markAllAsRead()}
                  sx={{ color: '#90caf9', minWidth: 'auto', p: 0.5 }}
                >
                  Mark All Read
                </Button>
              )}
              <IconButton
                size="small"
                onClick={() => notificationManager.clearAll()}
                sx={{ color: 'rgba(255,255,255,0.7)' }}
              >
                <ClearAll />
              </IconButton>
            </Box>
          </Box>
        </Box>

        {notifications.length === 0 ? (
          <Box sx={{ p: 3, textAlign: 'center' }}>
            <Typography variant="body2" sx={{ color: 'rgba(255,255,255,0.7)' }}>
              No notifications
            </Typography>
          </Box>
        ) : (
          <List sx={{ p: 0, maxHeight: 400, overflow: 'auto' }}>
            {notifications.map((notification, index) => (
              <React.Fragment key={notification.id}>
                <ListItem
                  sx={{
                    cursor: 'pointer',
                    backgroundColor: notification.read ? 'transparent' : 'rgba(144, 202, 249, 0.08)',
                    '&:hover': { backgroundColor: 'rgba(255, 255, 255, 0.05)' },
                    flexDirection: 'column',
                    alignItems: 'flex-start',
                    py: 1.5,
                  }}
                  onClick={() => handleNotificationClick(notification)}
                >
                  <Box sx={{ display: 'flex', width: '100%', alignItems: 'flex-start', gap: 1 }}>
                    <ListItemIcon sx={{ minWidth: 'auto', mt: 0.5 }}>
                      {getIcon(notification.type)}
                    </ListItemIcon>
                    <Box sx={{ flex: 1, minWidth: 0 }}>
                      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 0.5 }}>
                        <Typography
                          variant="subtitle2"
                          sx={{
                            color: 'white',
                            fontWeight: notification.read ? 400 : 600,
                            lineHeight: 1.2,
                          }}
                        >
                          {notification.title}
                        </Typography>
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5, ml: 1 }}>
                          <Typography
                            variant="caption"
                            sx={{ color: 'rgba(255,255,255,0.5)', whiteSpace: 'nowrap' }}
                          >
                            {formatTime(notification.timestamp)}
                          </Typography>
                          <IconButton
                            size="small"
                            onClick={(e) => {
                              e.stopPropagation();
                              notificationManager.removeNotification(notification.id);
                            }}
                            sx={{ 
                              color: 'rgba(255,255,255,0.3)', 
                              padding: 0.25,
                              '&:hover': { color: 'rgba(255,255,255,0.7)' }
                            }}
                          >
                            <Clear fontSize="small" />
                          </IconButton>
                        </Box>
                      </Box>
                      <Typography
                        variant="body2"
                        sx={{
                          color: 'rgba(255,255,255,0.8)',
                          lineHeight: 1.3,
                          wordBreak: 'break-word',
                        }}
                      >
                        {notification.message}
                      </Typography>
                      {notification.taskId && (
                        <Chip
                          label={`Task: ${notification.taskId.substring(0, 8)}...`}
                          size="small"
                          sx={{
                            mt: 0.5,
                            height: 20,
                            fontSize: '0.7rem',
                            backgroundColor: 'rgba(144, 202, 249, 0.2)',
                            color: '#90caf9',
                          }}
                        />
                      )}
                    </Box>
                  </Box>
                </ListItem>
                {index < notifications.length - 1 && <Divider sx={{ borderColor: '#333' }} />}
              </React.Fragment>
            ))}
          </List>
        )}
      </Popover>
    </>
  );
};

export default NotificationCenter; 