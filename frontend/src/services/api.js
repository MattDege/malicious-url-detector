import axios from 'axios';

const API_BASE_URL = 'http://localhost:8000';

export const scanURL = async (url) => {
  try {
    const response = await axios.post(`${API_BASE_URL}/scan`, {
      url: url
    });
    return response.data;
  } catch (error) {
    console.error('API Error:', error);
    throw error;
  }
};