import Restful from '../../';
import {
  CancellationSearchParams,
  ConfirmRefundRequest,
  CreateCancelRequest,
  RejectCancelRequest
} from '../../../../types';

/**
 * Post-Order Cancellation API
 */
export default class Cancellation extends Restful {
  get basePath(): string {
    return '/post-order/v2';
  }

  public useIaf() {
    return true;
  }

  /**
   * Seller approves a cancellation request
   *
   * @param cancelId The unique eBay-assigned identifier of the cancellation request to be approved.
   */
  public approveCancellationRequest(cancelId: string) {
    const id = encodeURIComponent(cancelId);
    return this.post(`/cancellation/${id}/approve`);
  }

  /**
   * Check the eligibility of an order cancellation
   *
   * @param legacyOrderId The unique ID of the order being canceled or the order being considered for cancellation.
   */
  public checkCancellationEligibility(legacyOrderId: string) {
    return this.post(`/cancellation/check_eligibility`, {
      legacyOrderId
    });
  }

  /**
   * Buyer confirms the refund from a cancellation was received
   *
   * @param cancelId The unique eBay-assigned identifier of the cancellation/refund being confirmed.
   * @param payload the ConfirmRefundReceivedPayload
   */
  public confirmRefundReceived(cancelId: string, payload?: ConfirmRefundRequest) {
    const id = encodeURIComponent(cancelId);
    return this.post(`/cancellation/${id}/confirm`, payload);
  }

  /**
   * Request or perform an order cancellation.
   *
   * @param payload the CreateCancelRequest
   */
  public createCancellation(payload: CreateCancelRequest) {
    return this.post(`/cancellation`, payload);
  }

  /**
   * Retrieve the details of an order cancellation.
   *
   * @param cancelId Supply in this path parameter the unique eBay-assigned ID of the cancellation request to
   *     retrieve.
   * @param fieldGroups    The value set in this query parameter controls the level of detail that is returned in the
   *     response.
   */
  public getCancellation(cancelId: string, fieldGroups?: string) {
    const id = encodeURIComponent(cancelId);
    return this.get(`/cancellation/${id}`, {
      params: {
        fieldgroups: fieldGroups
      }
    });
  }

  /**
   * Seller rejects a cancellation request.
   *
   * @param cancelId The unique eBay-assigned identifier of the cancellation request to be rejected.
   * @param payload the RejectCancelRequest
   */
  public rejectCancellationRequest(cancelId: string, payload?: RejectCancelRequest) {
    const id = encodeURIComponent(cancelId);
    return this.post(`/cancellation/${id}/reject`, payload);
  }

  /**
   * Search for cancellations.
   *
   * @param params the SearchParams
   */
  public search(params: CancellationSearchParams) {
    return this.get(`/cancellation/search`, {
      params: {
        params
      }
    });
  }
}
