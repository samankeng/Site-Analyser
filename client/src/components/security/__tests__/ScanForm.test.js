import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { BrowserRouter } from 'react-router-dom';
import ScanForm from '../ScanForm';
import { scanService } from '../../../services/scanService';

jest.mock('../../../services/scanService');

const renderWithRouter = (ui) => render(<BrowserRouter>{ui}</BrowserRouter>);

describe('ScanForm', () => {
  beforeEach(() => {
    scanService.createScan.mockClear();
  });

  it('renders form fields and buttons', () => {
    renderWithRouter(<ScanForm />);

    expect(screen.getByLabelText(/Target URL/i)).toBeInTheDocument();

    // Use a unique version of "Select All" — the one with (X/Y)
    const selectAllButtons = screen.getAllByRole('button', { name: /Select All/i });
    const globalToggle = selectAllButtons.find(btn =>
      btn.textContent.includes('(') && btn.textContent.includes('/')
    );
    expect(globalToggle).toBeInTheDocument();

    expect(screen.getByRole('button', { name: /Start Scan/i })).toBeInTheDocument();
  });

  it('shows error if no URL is entered', async () => {
    renderWithRouter(<ScanForm />);
    fireEvent.click(screen.getByRole('button', { name: /Start Scan/i }));
    expect(await screen.findByText(/Please enter a URL to scan/i)).toBeInTheDocument();
  });

  it('shows error if no scan type is selected', async () => {
    renderWithRouter(<ScanForm />);
  
    fireEvent.change(screen.getByLabelText(/Target URL/i), {
      target: { value: 'https://example.com' },
    });
  
    // Find global toggle button (with "(X/Y)" in label)
    const selectAllButtons = screen.getAllByRole('button', { name: /Select All/i });
    const globalToggle = selectAllButtons.find(btn => /\(\d+\/\d+\)/.test(btn.textContent));
    expect(globalToggle).toBeInTheDocument();
  
    // Click once to select all
    fireEvent.click(globalToggle);
  
    // Click again to deselect all
    fireEvent.click(globalToggle);
  
    // Verify all checkboxes are now unchecked
    const checkedBoxes = screen.getAllByRole('checkbox').filter(cb => cb.checked);
    expect(checkedBoxes.length).toBe(0);
  
    // Submit form
    fireEvent.click(screen.getByRole('button', { name: /Start Scan/i }));
  
    // Expect error
    await waitFor(() => {
      expect(screen.getByRole('alert')).toHaveTextContent(/select at least one scan type/i);
    });
  });
  
  
  

  it('submits form and redirects on success', async () => {
    scanService.createScan.mockResolvedValue({
      success: true,
      data: { id: '123' },
    });

    renderWithRouter(<ScanForm />);
    fireEvent.change(screen.getByLabelText(/Target URL/i), {
      target: { value: 'https://example.com' },
    });

    fireEvent.click(screen.getByRole('button', { name: /Start Scan/i }));

    await waitFor(() => {
      expect(scanService.createScan).toHaveBeenCalledWith({
        target_url: 'https://example.com',
        scan_types: expect.any(Array),
      });
    });
  });
});
